using Sandbox;

/// <summary>Loads a mounted HROT JPG, TGA, JPEG, or PNG texture.</summary>
class HrotTexture( string pakDir, string fileName ) : ResourceLoader<HrotMount>
{
	public string PakDir { get; set; } = pakDir;
	public string FileName { get; set; } = fileName;

	protected override object Load()
	{
		return Host.LoadTexture( PakDir, FileName ) ?? Texture.Invalid;
	}
}
