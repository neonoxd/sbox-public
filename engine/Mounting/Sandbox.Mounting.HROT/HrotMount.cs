using Sandbox;
using Sandbox.Mounting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using HrotPakLib;

/// <summary>A mounting implementation for HROT.</summary>
public sealed class HrotMount : BaseGameMount
{
	static readonly HashSet<string> VerticallyFlippedModelUvs = new( StringComparer.OrdinalIgnoreCase )
	{
		// spawn.md2 embeds DALSI15.PSD, but its stored T coordinates use the
		// opposite convention from most HROT MD2 exports.
		"spawn"
	};

	public override string Ident => "hrot";
	public override string Title => "HROT";
	public override long? SteamAppId => 824600;

	readonly CaseInsensitiveDictionary<List<HrotPak>> _paks = [];
	readonly CaseInsensitiveDictionary<Texture> _textures = [];
	readonly Dictionary<int, HrotMapGrid> _maps = [];
	Dictionary<int, HrotStaticModelRegistration> _staticModels = [];
	Dictionary<int, string> _mapNames = [];
	Dictionary<int, string> _sounds = [];
	Dictionary<int, HrotModelSound> _modelSounds = [];
	Dictionary<int, HrotMapMusic> _mapMusic = [];
	CaseInsensitiveDictionary<string> _executableModelTextures = [];

	string _root;

	// Mounted resource path prefixes. FindStaticModelPath returns a path built
	// with ModelPrefix because Model.Load resolves the *registered* name -
	// see ResourceLoader - so the two must not drift apart.
	const string ModelPrefix = "models/";

	// Every 3DS is registered a second time under this marker, carrying a convex
	// hull instead of a concave collision mesh. The level's own props keep the
	// mesh - their colliders are static, so it is both exact and free - but a
	// mesh shape cannot be simulated, so dragging one into a scene produced a
	// Rigidbody with no volume that fell through the world. These copies are the
	// droppable ones. MD2s need no equivalent: they carry no physics part at
	// all, so Prop never gives them a body in the first place.
	//
	// It goes in the file name rather than in a directory of its own: the two
	// then sort together in the asset browser, and ResourceLoader takes Name
	// from the file name, so the marker rides along on the model itself.
	const string PropVariantMarker = "(PROP) ";

	static string PropVariantPath( string fullPath )
	{
		var slash = fullPath.LastIndexOf( '/' );

		return slash < 0
			? PropVariantMarker + fullPath
			: string.Concat(
				fullPath.AsSpan( 0, slash + 1 ),
				PropVariantMarker,
				fullPath.AsSpan( slash + 1 ) );
	}
	const string TexturePrefix = "textures/";
	const string SoundPrefix = "sounds/";

	/// <summary>
	/// The shader every HROT surface uses.
	/// </summary>
	/// <remarks>
	/// Samples the texture's alpha channel. HROT's cutout textures - ladders
	/// (<c>blendigo.tga</c>), railings and grates (<c>blendigo2.tga</c>) and the
	/// glass (<c>sklo.tga</c>) - are 32-bit TGAs whose alpha is the transparency,
	/// so a shader that ignores it renders them solid.
	/// </remarks>
	public const string SurfaceShader = "shaders/hrot_color.shader";

	/// <summary>How a texture's alpha channel should be rendered.</summary>
	public enum AlphaKind
	{
		/// <summary>No alpha channel. Draw opaque.</summary>
		None,
		/// <summary>Alpha is effectively 0 or 255. Alpha test.</summary>
		Cutout,
		/// <summary>Alpha has intermediate values. Blend.</summary>
		Blended
	}

	readonly CaseInsensitiveDictionary<AlphaKind> _alphaKinds = [];

	/// <summary>Classifies a texture's alpha channel.</summary>
	/// <remarks>
	/// The distinction matters because the two modes are mutually exclusive in
	/// the shader, and picking the wrong one is very visible: alpha-testing
	/// <c>sklo.tga</c> clips its graded alpha into a hard-edged cutout instead
	/// of glass, and blending the binary <c>blendigo</c> atlases would put
	/// ladders and railings into the sorted pass for no reason.
	///
	/// Only TGA can carry alpha in HROT's shipped data - the PAKs hold TGA,
	/// JPG, 3DS, MD2 and WAV - so the 18-byte header settles most of it: byte
	/// 16 is the pixel depth, and 32 means BGRA. Deciding cutout from blended
	/// needs the pixels, so those are sampled. Results are cached; a 1 MB TGA
	/// is otherwise re-read for every model that uses it.
	/// </remarks>
	public AlphaKind TextureAlphaKind( string pakDir, string filename )
	{
		if ( string.IsNullOrWhiteSpace( filename ) ||
			!Path.GetExtension( filename ).Equals( ".tga", StringComparison.OrdinalIgnoreCase ) )
			return AlphaKind.None;

		var key = CombineVirtual( pakDir, Normalize( filename ) );
		if ( _alphaKinds.TryGetValue( key, out var cached ) )
			return cached;

		return _alphaKinds[key] = ClassifyTgaAlpha( GetFileBytes( pakDir, filename ) );
	}

	static AlphaKind ClassifyTgaAlpha( byte[] tga )
	{
		// 18-byte header; byte 16 is the pixel depth, byte 0 an optional id
		// field whose length shifts the pixel data.
		if ( tga is not { Length: > 18 } || tga[16] != 32 )
			return AlphaKind.None;

		// Only uncompressed true-colour is worth walking directly. HROT ships
		// nothing else, but an RLE image would need decoding, so treat it as a
		// plain cutout rather than mis-sampling compressed bytes.
		if ( tga[2] != 2 )
			return AlphaKind.Cutout;

		var start = 18 + tga[0];
		var intermediate = 0;
		var sampled = 0;

		// Stride is a prime multiple of the pixel size so the walk does not
		// land on the same column of a tiled image every time.
		for ( var i = start + 3; i < tga.Length; i += 4 * 101 )
		{
			var alpha = tga[i];
			sampled++;
			if ( alpha is > 16 and < 239 )
				intermediate++;
		}

		if ( sampled == 0 )
			return AlphaKind.None;

		// blendigo/blendigo2 come out near 0% intermediate; sklo.tga is far
		// above this, so the threshold is not delicately placed.
		return intermediate * 100 / sampled >= 5
			? AlphaKind.Blended
			: AlphaKind.Cutout;
	}

	/// <summary>True when a texture file carries an alpha channel at all.</summary>
	public bool TextureHasAlpha( string pakDir, string filename )
		=> TextureAlphaKind( pakDir, filename ) != AlphaKind.None;

	/// <summary>
	/// <see cref="TextureHasAlpha"/> against whichever PAK directory holds the
	/// file, mirroring <see cref="LoadTextureAnywhere"/>.
	/// </summary>
	public AlphaKind TextureAlphaKindAnywhere( string filename )
	{
		if ( string.IsNullOrWhiteSpace( filename ) )
			return AlphaKind.None;

		filename = Normalize( filename );
		foreach ( var pakDir in _paks.Keys )
			if ( FileExists( pakDir, filename ) )
				return TextureAlphaKind( pakDir, filename );

		return AlphaKind.None;
	}

	/// <summary>
	/// Whether the texture a model names by stem carries alpha. 3DS models
	/// store a stem with a stale extension, so only the stem is meaningful -
	/// and since alpha implies TGA, that is the only extension worth trying.
	/// </summary>
	public AlphaKind TextureStemAlphaKindAnywhere( string filename )
		=> string.IsNullOrWhiteSpace( filename )
			? AlphaKind.None
			: TextureAlphaKindAnywhere(
				Path.GetFileNameWithoutExtension( Normalize( filename ) ) + ".tga" );

	/// <summary>
	/// Applies the alpha mode a texture needs. The two are mutually exclusive -
	/// the shader declares a FeatureRule saying so.
	/// </summary>
	public static void ApplyAlphaMode( Material material, AlphaKind kind )
	{
		if ( material is null )
			return;

		switch ( kind )
		{
			case AlphaKind.Cutout:
				material.SetFeature( "F_ALPHA_TEST", 1 );
				material.Set( "g_flAlphaTestReference", 0.5f );
				break;
			case AlphaKind.Blended:
				material.SetFeature( "F_TRANSLUCENT", 1 );
				break;
		}
	}

	protected override void Initialize( InitializeContext context )
	{
		if ( !context.IsAppInstalled( SteamAppId.Value ) )
			return;

		_root = context.GetAppDirectory( SteamAppId.Value );
		if ( string.IsNullOrWhiteSpace( _root ) || !System.IO.Directory.Exists( _root ) )
			return;

		foreach ( var pakPath in System.IO.Directory.EnumerateFiles( _root, "*.pak", SearchOption.AllDirectories ) )
		{
			var pakDirPath = Path.GetDirectoryName( pakPath );
			if ( pakDirPath is null ) continue;

			var pakDir = Path.GetRelativePath( _root, pakDirPath ).Replace( '\\', '/' );
			if ( pakDir == "." ) pakDir = string.Empty;

			var pak = new HrotPak( pakPath );
			if ( !pak.IsValid )
			{
				pak.Dispose();
				continue;
			}

			if ( !_paks.TryGetValue( pakDir, out var list ) )
				_paks[pakDir] = list = [];

			list.Add( pak );
		}

		foreach ( var list in _paks.Values )
			list.Sort( ( a, b ) => string.Compare( b.Name, a.Name, StringComparison.OrdinalIgnoreCase ) );

		var md2Names = new HashSet<string>( StringComparer.OrdinalIgnoreCase );
		foreach ( var pakList in _paks.Values )
		{
			foreach ( var pak in pakList )
			{
				foreach ( var file in pak.Files )
				if ( Path.GetExtension( file.FullPath ).Equals( ".md2", StringComparison.OrdinalIgnoreCase ) )
					md2Names.Add( Path.GetFileNameWithoutExtension( file.FullPath ) );
			}
		}

		var executableAssignments = HrotExecutableTextureMap.Read( Path.Combine( _root, "HROT.exe" ) );
		_staticModels = HrotExecutableStaticModels.Read( Path.Combine( _root, "HROT.exe" ) );
		_mapNames = HrotExecutableMapData.ReadMapNames( Path.Combine( _root, "HROT.exe" ) );
		_sounds = HrotExecutableSounds.Read( Path.Combine( _root, "HROT.exe" ) );
		_modelSounds = HrotExecutableSounds.ReadModelSounds( Path.Combine( _root, "HROT.exe" ) );
		_mapMusic = HrotExecutableSounds.ReadMapMusic( Path.Combine( _root, "HROT.exe" ) );
		_executableModelTextures = new CaseInsensitiveDictionary<string>();
		foreach ( var (model, texture) in executableAssignments )
			if ( md2Names.Contains( model ) )
				_executableModelTextures[model] = texture;

		Log.Info( $"Recovered {_executableModelTextures.Count} MD2 texture assignments from HROT.exe." );
		Log.Info( $"Recovered {_staticModels.Count} HROT static model registrations from HROT.exe." );
		Log.Info( $"Recovered {_sounds.Count} HROT sound registrations from HROT.exe." );
		Log.Info( $"Recovered {_modelSounds.Count} models that emit a looping sound." );
		Log.Info( $"Recovered music layers for {_mapMusic.Count} maps." );
		if ( _mapNames.Count > 0 )
			Log.Info( $"Recovered {_mapNames.Count} HROT level names from HROT.exe." );
		else
			Log.Warning( "HROT level names could not be read; scenes fall back to \"Map NN\"." );

		IsInstalled = true;
	}

	protected override Task Mount( MountContext context )
	{
		var registered = new HashSet<string>( StringComparer.OrdinalIgnoreCase );

		// One scene per map.
		foreach ( var mapId in HrotExecutableMapData.MapIds )
		{
			// The decoded name is a suffix rather than the whole name so scenes
			// still sort by map id. When it is missing - an unrecognised build,
			// see HrotExecutableMapData.ReadMapNames - the suffix is dropped
			// rather than repeating the id as "Map 03 [Map 03]".
			var name = _mapNames.TryGetValue( mapId, out var decoded ) && !string.IsNullOrWhiteSpace( decoded )
				? decoded
				: null;

			context.Add(
				ResourceType.Scene,
				name is null ? $"maps/Map {mapId:00}.scene" : $"maps/Map {mapId:00} [{name}].scene",
				new HrotMap( mapId ) );
		}

		foreach ( var (pakDir, pakList) in _paks )
		{
			foreach ( var pak in pakList )
			{
				foreach ( var file in pak.Files )
					Register( context, registered, pakDir, file.FullPath );
			}
		}

		IsMounted = true;
		return Task.CompletedTask;
	}

	void Register( MountContext context, HashSet<string> registered, string pakDir, string path )
	{
		var ext = Path.GetExtension( path )?.ToLowerInvariant();
		if ( string.IsNullOrWhiteSpace( ext ) ) return;

		var fullPath = string.IsNullOrEmpty( pakDir )
			? path.Replace( '\\', '/' )
			: Path.Combine( pakDir, path ).Replace( '\\', '/' );

		if ( !registered.Add( fullPath ) ) return;

		switch ( ext )
		{
			case ".md2": context.Add( ResourceType.Model, $"{ModelPrefix}{fullPath}", new HrotModel( pakDir, path ) ); break;
			case ".3ds":
				context.Add( ResourceType.Model, $"{ModelPrefix}{fullPath}", new Hrot3dsModel( pakDir, path ) );
				context.Add( ResourceType.Model, $"{ModelPrefix}{PropVariantPath( fullPath )}",
					new Hrot3dsModel( pakDir, path, simulatable: true ) );
				break;
			case ".jpg":
			case ".jpeg":
			case ".tga":
			case ".png":
			case ".psd": context.Add( ResourceType.Texture, $"{TexturePrefix}{fullPath}", new HrotTexture( pakDir, path ) ); break;
			case ".wav": context.Add( ResourceType.Sound, $"{SoundPrefix}{fullPath}", new HrotSound( pakDir, path ) ); break;
		}
	}

	List<HrotPak> Paks( string pakDir ) => _paks.TryGetValue( pakDir ?? string.Empty, out var list ) ? list : [];

	public Stream GetFileStream( string pakDir, string filename )
	{
		var bytes = GetFileBytes( pakDir, filename );
		return bytes is null ? Stream.Null : new MemoryStream( bytes, writable: false );
	}

	public byte[] GetFileBytes( string pakDir, string filename, int maxLength = -1 )
	{
		filename = Normalize( filename );

		foreach ( var pak in Paks( pakDir ) )
		{
			var bytes = pak.GetFileBytes( filename, maxLength );
			if ( bytes is not null ) return bytes;
		}

		return null;
	}

	public bool FileExists( string pakDir, string filename )
	{
		filename = Normalize( filename );
		foreach ( var pak in Paks( pakDir ) )
			if ( pak.FileExists( filename ) ) return true;
		return false;
	}

	public Texture LoadTexture( string pakDir, string filename )
	{
		filename = Normalize( filename );
		var key = CombineVirtual( pakDir, filename );

		if ( _textures.TryGetValue( key, out var cached ) && cached is not null )
			return cached;

		var bytes = GetFileBytes( pakDir, filename );
		if ( bytes is null || bytes.Length == 0 )
		{
			Log.Warning( $"HROT texture '{key}' could not be read." );
			return null;
		}

		// Texture.Load/LoadAsync interprets strings as paths in an s&box
		// filesystem, so a Windows path such as D:/... is not valid here.
		// Bitmap decodes encoded image bytes directly (including JPG/PNG and
		// the engine's TGA fallback), then uploads the decoded pixels.
		using var bitmap = Bitmap.CreateFromBytes( bytes );
		if ( bitmap is null || !bitmap.IsValid )
		{
			Log.Warning( $"HROT texture '{key}' could not be decoded." );
			return null;
		}

		var texture = bitmap.ToTexture( true );
		if ( texture is null || !texture.IsValid )
		{
			Log.Warning( $"HROT texture '{key}' could not be uploaded." );
			return null;
		}

		_textures[key] = texture;
		return texture;
	}

	public Texture LoadTextureAnywhere( string filename )
	{
		filename = Normalize( filename );

		foreach ( var pakDir in _paks.Keys )
			if ( FileExists( pakDir, filename ) )
				return LoadTexture( pakDir, filename );

		Log.Warning( $"HROT texture '{filename}' was not found in any PAK." );
		return null;
	}

	public Texture LoadTextureByStemAnywhere( string filename )
	{
		if ( string.IsNullOrWhiteSpace( filename ) )
			return null;

		var stem = Path.GetFileNameWithoutExtension( Normalize( filename ) );
		foreach ( var extension in new[] { ".jpg", ".jpeg", ".tga", ".png", ".psd" } )
		{
			var texture = LoadTextureAnywhere( stem + extension );
			if ( texture is not null )
				return texture;
		}
		return null;
	}

	internal string GetStaticModelTexture( string model )
	{
		foreach ( var registration in _staticModels.Values )
			if ( registration.Model.Equals( model, StringComparison.OrdinalIgnoreCase ) )
				return registration.Texture;
		return null;
	}

	internal string GetStaticModelName( int id )
	{
		return _staticModels.TryGetValue( id, out var registration )
			? registration.Model
			: $"model_{id}";
	}

	internal float GetStaticModelYawOffset( int id )
	{
		return 0.0f;
	}

	internal string FindStaticModelPath( int id )
	{
		if ( !_staticModels.TryGetValue( id, out var registration ) )
			return null;

		var filename = Path.ChangeExtension( registration.Model, ".3DS" );
		foreach ( var pakDir in _paks.Keys )
			if ( FileExists( pakDir, filename ) )
				return ModelPrefix + CombineVirtual( pakDir, filename );

		return null;
	}

	internal string GetMapName( int mapId ) => HrotMapNames.Get( _mapNames, mapId );

	internal HrotMapGrid GetMapGrid( int mapId )
	{
		if ( _maps.TryGetValue( mapId, out var cached ) )
			return cached;

		var grid = HrotExecutableMapData.Read( Path.Combine( _root, "HROT.exe" ), mapId );
		if ( grid is not null )
		{
			_maps[mapId] = grid;
			Log.Info( $"Reconstructed HROT map {mapId} from {grid.WriteCount} executable grid writes." );
		}

		return grid;
	}

	internal List<HrotPropPlacement> GetMapProps( int mapId, HrotMapGrid grid )
	{
		return HrotExecutableProps.Read( Path.Combine( _root, "HROT.exe" ), mapId, grid );
	}

	internal List<HrotGlassPanel> GetMapGlassPanels( int mapId )
	{
		return HrotExecutableProps.ReadGlassPanels(
			Path.Combine( _root, "HROT.exe" ), mapId );
	}

	internal List<HrotDoorPlacement> GetMapDoors( int mapId )
	{
		return HrotExecutableProps.ReadDoors(
			Path.Combine( _root, "HROT.exe" ), mapId );
	}

	internal List<HrotDecalPlacement> GetMapDecals( int mapId, out int undecodable )
	{
		return HrotExecutableProps.ReadDecals(
			Path.Combine( _root, "HROT.exe" ), mapId, out undecodable );
	}

	internal List<HrotSignBox> GetMapSignBoxes( int mapId, out int undecodable )
	{
		return HrotExecutableProps.ReadSignBoxes(
			Path.Combine( _root, "HROT.exe" ), mapId, out undecodable );
	}

	/// <summary>
	/// The looping sound a static model emits, decoded from its update case.
	/// </summary>
	internal HrotModelSound? GetStaticModelSound( int modelId )
		=> _modelSounds.TryGetValue( modelId, out var sound ) ? sound : null;

	/// <summary>The mounted path of a sound file.</summary>
	/// <remarks>
	/// The <c>.vsnd</c> suffix is required: a mount registers a sound under its
	/// own name but resolves it through the engine extension, exactly as models
	/// resolve through <c>.vmdl</c>. Without it <c>SoundFile.Load</c> finds
	/// nothing, and the resulting SoundEvent is silent rather than missing.
	/// </remarks>
	internal string GetSoundPath( string filename )
		=> $"mount://{Ident}/{SoundPrefix}{filename}.vsnd";

	/// <summary>The music layers a map plays, or null if it sets none.</summary>
	internal HrotMapMusic? GetMapMusic( int mapId )
		=> _mapMusic.TryGetValue( mapId, out var music ) ? music : null;

	/// <summary>A sound id's registered filename.</summary>
	internal string GetSoundName( int soundId )
		=> _sounds.TryGetValue( soundId, out var name ) ? name : null;

	internal HrotPlayerSpawn? GetMapPlayerSpawn( int mapId )
	{
		return HrotExecutableProps.ReadPlayerSpawn(
			Path.Combine( _root, "HROT.exe" ), mapId );
	}

	internal string GetMapDecalSheet( int mapId )
	{
		return HrotExecutableProps.ReadDecalSheet(
			Path.Combine( _root, "HROT.exe" ), mapId );
	}

	public string ResolveModelTexture( string pakDir, string modelFile, IReadOnlyList<string> skins )
	{
		var modelDirectory = Path.GetDirectoryName( modelFile )?.Replace( '\\', '/' ) ?? string.Empty;
		string[] textureExtensions = [".jpg", ".jpeg", ".tga", ".png", ".psd"];

		foreach ( var skin in skins )
		{
			if ( string.IsNullOrWhiteSpace( skin ) ) continue;
			var normalized = Normalize( skin );
			if ( FileExists( pakDir, normalized ) ) return normalized;

			var basename = Path.GetFileName( normalized );
			var besideModel = CombineVirtual( modelDirectory, basename );
			if ( FileExists( pakDir, besideModel ) ) return besideModel;

			// HROT's MD2s sometimes retain development-time PSD skin names,
			// while the shipped texture was converted to JPG/TGA. Preserve the
			// referenced stem and try each image format rather than falling
			// back to the model's unrelated basename.
			var skinStem = Path.GetFileNameWithoutExtension( basename );
			var skinDirectory = Path.GetDirectoryName( normalized )?.Replace( '\\', '/' ) ?? string.Empty;
			foreach ( var extension in textureExtensions )
			{
				var convertedName = skinStem + extension;
				var referencedDirectory = CombineVirtual( skinDirectory, convertedName );
				if ( FileExists( pakDir, referencedDirectory ) ) return referencedDirectory;

				var convertedBesideModel = CombineVirtual( modelDirectory, convertedName );
				if ( FileExists( pakDir, convertedBesideModel ) ) return convertedBesideModel;
			}
		}

		var stem = Path.GetFileNameWithoutExtension( modelFile );
		foreach ( var ext in textureExtensions )
		{
			var candidate = CombineVirtual( modelDirectory, stem + ext );
			if ( FileExists( pakDir, candidate ) ) return candidate;
		}

		var modelName = Path.GetFileNameWithoutExtension( modelFile );
		if ( _executableModelTextures.TryGetValue( modelName, out var executableTexture ) )
		{
			foreach ( var extension in textureExtensions )
			{
				var convertedName = Path.ChangeExtension( executableTexture, extension );
				var besideModel = CombineVirtual( modelDirectory, convertedName );
				if ( FileExists( pakDir, besideModel ) ) return besideModel;
				if ( FileExists( pakDir, convertedName ) ) return convertedName;
			}
		}

		// No manual fallback table: every assignment is recovered from the
		// executable by the three patterns in HrotExecutableTextureMap - the
		// weapons and nakladac/kosmonaut by the static and weapon patterns, and
		// gimp/kapic/kapic2/kapicmoto/holub by the actor pattern. See
		// REVERSE_ENGINEERING.md section 4.
		Log.Warning(
			$"HROT model '{modelFile}' has no texture in its own file and none " +
			"recovered from HROT.exe." );
		return null;
	}

	public bool ShouldFlipModelUvVertically( string modelFile )
	{
		return VerticallyFlippedModelUvs.Contains( Path.GetFileNameWithoutExtension( modelFile ) );
	}

	protected override void Shutdown()
	{
		foreach ( var pakList in _paks.Values )
			foreach ( var pak in pakList ) pak.Dispose();

		_paks.Clear();
		_textures.Clear();
		_maps.Clear();
		_staticModels.Clear();
		_mapNames.Clear();
		_executableModelTextures.Clear();

	}

	static string CombineVirtual( string a, string b ) => string.IsNullOrEmpty( a ) ? Normalize( b ) : Normalize( $"{a}/{b}" );
	static string Normalize( string path ) => path.Replace( '\\', '/' ).TrimStart( '/' );
}
