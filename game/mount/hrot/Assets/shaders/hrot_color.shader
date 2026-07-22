HEADER
{
	Description = "HROT mounted surfaces. Like the Quake mount's simple_color, but it samples the texture's alpha instead of discarding it.";
}

FEATURES
{
	#include "common/features.hlsl"
	// Neither of these is in common/features.hlsl - it declares only
	// F_TEXTURE_FILTERING and F_ADDITIVE_BLEND - so they have to be declared
	// here, as the SE3 mount's shader does for F_ALPHA_TEST. Without the
	// declaration the matching SetFeature call from C# is a silent no-op and
	// the surface renders solid.
	//
	// HROT needs both: blendigo/blendigo2 have binary alpha and want testing,
	// sklo.tga has graded alpha and wants blending.
	Feature( F_ALPHA_TEST, 0..1, "Translucent" );
	Feature( F_TRANSLUCENT, 0..1, "Translucent" );
	// Must stay on one line - the rule parser rejects a line break inside it.
	FeatureRule( Allow1( F_ALPHA_TEST, F_TRANSLUCENT ), "Translucent and Alpha Test are not compatible" );
}

MODES
{
    Forward();
    Depth();
}

COMMON
{
	#include "common/shared.hlsl"
}

struct VertexInput
{
	#include "common/vertexinput.hlsl"
};

struct PixelInput
{
	#include "common/pixelinput.hlsl"
};

VS
{
	#include "common/vertex.hlsl"

	PixelInput MainVs( VertexInput v )
	{
		PixelInput i = ProcessVertex( v );
		return FinalizeVertex( i );
	}
}

PS
{
	#include "common/pixel.hlsl"

	// sbox_pixel.fxc turns these combos into actual render state - depth write
	// off and SRC_ALPHA/INV_SRC_ALPHA blending for translucent, alpha-to-
	// coverage for alpha test - and declares g_flAlphaTestReference and
	// g_flOpacityScale alongside them. Declaring either parameter here as well
	// would be a duplicate definition, so the shader only supplies Opacity.
	StaticCombo( S_ALPHA_TEST, F_ALPHA_TEST, Sys( ALL ) );
	StaticCombo( S_TRANSLUCENT, F_TRANSLUCENT, Sys( ALL ) );

	// Nearest-neighbour, like the Quake mount's shader. HROT's textures are
	// 64px tiles on walls the player stands right next to, and filtering them
	// smears the pixel art the whole game is drawn in.
	//
	// Plain Point rather than a mixed min/mag filter because the shader
	// compiler does not validate filter names: NOT_A_REAL_FILTER compiles just
	// as "successfully" as a real one, so a clever filter that this engine does
	// not recognise would silently do nothing. Point is proven in-repo.
	SamplerState g_sSampler0 < Filter( Point ); AddressU( WRAP ); AddressV( WRAP ); >;
	CreateInputTexture2D( Color, Srgb, 8, "None", "_color", ",0/,0/0", Default4( 1.00, 1.00, 1.00, 1.00 ) );
	Texture2D g_tColor < Channel( RGBA, Box( Color ), Srgb ); OutputFormat( DXT5 ); SrgbRead( true ); >;

	float4 MainPs( PixelInput i ) : SV_Target0
	{
		Material m = Material::Init();

		float4 colour = Tex2DS( g_tColor, g_sSampler0, i.vTextureCoords.xy );

		m.Albedo = colour.rgb;
		m.Normal = i.vNormalWs;
		m.TextureCoords = i.vTextureCoords.xy;
		m.Roughness = 1;
		m.Metalness = 0;
		m.AmbientOcclusion = 1;
		m.TintMask = 1;
		// The whole point of this shader. simple_color hardcodes Opacity = 1
		// and samples only .rgb, so HROT's cutout textures - blendigo.tga for
		// ladders, blendigo2.tga for railings and grates, sklo.tga for glass -
		// render solid.
		m.Opacity = colour.a;
		#if ( S_TRANSLUCENT )
			m.Opacity *= g_flOpacityScale;
		#endif
		m.Emission = 0;
		m.Transmission = 0;

		return ShadingModelStandard::Shade( i, m );
	}
}
