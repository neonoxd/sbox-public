using Sandbox;
using System.IO;

/// <summary>Loads one of HROT's WAV sounds.</summary>
/// <remarks>
/// HROT ships 423 WAVs, all in the PAK root and all plain RIFF/WAVE - mono and
/// stereo, 8 and 16 bit, at 22050, 44100 and 48000 Hz. <c>SoundFile.FromWav</c>
/// handles every one of those, so nothing is converted here.
///
/// <b>Nothing is marked as looping.</b> Not one of the 423 carries a
/// <c>smpl</c> chunk, and unlike Quake - where the mount can key off the
/// <c>ambience/</c> directory - HROT keeps every sound in one flat namespace.
/// So which sounds loop is not in the data at all; it is a property of the code
/// that plays them, and inventing a rule from the file names would be guessing.
/// Ambient beds like <c>ambient2.wav</c> will play once until something decodes
/// HROT's own playback calls.
/// </remarks>
sealed class HrotSound( string pakDir, string fileName ) : ResourceLoader<HrotMount>
{
	protected override object Load()
	{
		var data = Host.GetFileBytes( pakDir, fileName );
		if ( data is null || data.Length == 0 )
			throw new InvalidDataException( $"Unable to read WAV: {fileName}" );

		return SoundFile.FromWav( Path, data );
	}
}
