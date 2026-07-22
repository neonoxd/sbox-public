using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace HrotPakLib;

public sealed class HrotPakFile
{
	public string FullPath { get; init; }
	public int Offset { get; init; }
	public int Length { get; init; }
}

public sealed class HrotPak : IDisposable
{
	readonly FileStream _stream;
	readonly Dictionary<string, HrotPakFile> _lookup = new( StringComparer.OrdinalIgnoreCase );

	public string Path { get; }
	public string Name => System.IO.Path.GetFileName( Path );
	public IReadOnlyList<HrotPakFile> Files { get; }
	public bool IsValid { get; }

	public HrotPak( string path )
	{
		Path = path;
		_stream = File.OpenRead( path );
		using var br = new BinaryReader( _stream, Encoding.UTF8, leaveOpen: true );

		if ( Encoding.ASCII.GetString( br.ReadBytes( 4 ) ) != "HROT" )
		{
			Files = Array.Empty<HrotPakFile>();
			return;
		}

		var tableOffset = br.ReadUInt32();
		var tableLength = br.ReadUInt32();

		if ( tableLength == 0 || tableLength % 128 != 0 || tableOffset + tableLength > _stream.Length )
		{
			Files = Array.Empty<HrotPakFile>();
			return;
		}

		var files = new List<HrotPakFile>( checked((int)(tableLength / 128)) );
		_stream.Position = tableOffset;

		for ( var i = 0; i < tableLength / 128; i++ )
		{
			var rawName = br.ReadBytes( 120 );
			var zero = Array.IndexOf( rawName, (byte)0 );
			var nameLength = zero >= 0 ? zero : rawName.Length;
			var name = Encoding.UTF8.GetString( rawName, 0, nameLength ).Replace( '\\', '/' ).TrimStart( '/' );
			var offset = br.ReadUInt32();
			var length = br.ReadUInt32();

			if ( string.IsNullOrWhiteSpace( name ) || offset + length > _stream.Length )
				continue;

			var file = new HrotPakFile
			{
				FullPath = name,
				Offset = checked((int)offset),
				Length = checked((int)length)
			};

			files.Add( file );
			_lookup[name] = file;
		}

		Files = files;
		IsValid = true;
	}

	public bool FileExists( string filename )
	{
		return !string.IsNullOrWhiteSpace( filename ) && _lookup.ContainsKey( Normalize( filename ) );
	}

	public byte[] GetFileBytes( string filename, int maxLength = -1 )
	{
		if ( !_lookup.TryGetValue( Normalize( filename ), out var file ) )
			return null;

		var count = maxLength >= 0 ? Math.Min( maxLength, file.Length ) : file.Length;
		var result = new byte[count];

		lock ( _stream )
		{
			_stream.Position = file.Offset;
			_stream.ReadExactly( result );
		}

		return result;
	}

	static string Normalize( string path ) => path.Replace( '\\', '/' ).TrimStart( '/' );

	public void Dispose()
	{
		_stream.Dispose();
		GC.SuppressFinalize( this );
	}
}
