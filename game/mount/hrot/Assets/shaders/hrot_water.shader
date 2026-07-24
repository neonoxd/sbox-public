HEADER
{
	Description = "HROT animated water. Port of HROT's own GLSL water shader (its 06_frag_water + 12_vert_water, extracted by Tools/dump_shaders.py): voda1 scrolled and warped by the vodanorm normal map, driven by time.";
}

FEATURES
{
	#include "common/features.hlsl"
	// common/features.hlsl declares only F_TEXTURE_FILTERING and
	// F_ADDITIVE_BLEND, so this has to be declared here or the matching
	// SetFeature call from C# is a silent no-op and the water renders solid.
	Feature( F_TRANSLUCENT, 0..1, "Translucent" );
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

	// The Feature declaration alone does nothing: this is what sbox_pixel.fxc
	// turns into actual render state (depth write off, SRC_ALPHA/INV_SRC_ALPHA
	// blending) and what declares g_flOpacityScale. Without it the shader still
	// compiles, with the same combo count, and the water stays solid - watch the
	// PS combo count in the compiler output, it should double.
	StaticCombo( S_TRANSLUCENT, F_TRANSLUCENT, Sys( ALL ) );

	// Nearest-neighbour for the base texture, matching hrot_color: HROT is pixel
	// art and bilinear smears it. The distortion map wants smooth sampling
	// though, so it gets its own bilinear/wrap sampler - the warp is a continuous
	// offset, not something to quantise into blocks.
	SamplerState g_sSampler0 < Filter( Point ); AddressU( WRAP ); AddressV( WRAP ); >;
	SamplerState g_sDist < Filter( Anisotropic ); AddressU( WRAP ); AddressV( WRAP ); >;

	// BaseMap = voda1.jpg, the water colour.
	CreateInputTexture2D( Color, Srgb, 8, "None", "_color", ",0/,0/0", Default4( 1.00, 1.00, 1.00, 1.00 ) );
	Texture2D g_tColor < Channel( RGBA, Box( Color ), Srgb ); OutputFormat( DXT5 ); SrgbRead( true ); >;

	// DistMap = vodanorm.jpg, a normal map. Read linear (not sRGB): its RGB
	// encode a direction, not a colour.
	CreateInputTexture2D( Dist, Linear, 8, "None", "_dist", ",0/,0/0", Default4( 0.50, 0.50, 1.00, 1.00 ) );
	Texture2D g_tDistMap < Channel( RGBA, Box( Dist ), Linear ); OutputFormat( DXT5 ); SrgbRead( false ); >;

	// Literal constants from HROT's GLSL:
	//   c        = v_coords*u_k - u_k*0.5,   u_k = (15,-15)
	//   wobble   = sin((c.x + c.y + u_time*0.5) / 2.5) * 0.04   added to both uv axes
	//   warp     = (DistMap.rgb*2-1).xy * 0.04
	//   scroll   = v_coords.y += transp.z * u_time   (in the vertex shader)
	static const float kWobbleFreq = 2.5;
	static const float kWobbleAmp = 0.04;
	static const float kWarpAmp = 0.04;

	// HROT's water shader setup binds
	//     u_time = [0x17D76A8] * 0.06 * 2.0
	// where 0x17D76A8 is the sim-tick counter, incremented once per fixed tick
	// right after the object walker at 0x00D4F7FC, at 100 Hz. So u_time advances
	// 0.12 * 100 = 12.0 per second, and g_flTime is seconds.
	static const float kHrotTimeScale = 12.0;

	// The flow rate is the geometry's vertex colour BLUE channel:
	//     v_coords.y += transp.z * u_time,     transp = gl_Color.rgb
	// One shader draws pools and waterfalls alike; the split is the colour. The
	// water grid pass sets glColor3f(0.8, 0.91, 0) and (0.55, 0.9, 0) for its two
	// water types - blue 0, so pools wobble without flowing. Red and green are the
	// alpha clamp.
	//
	// The waterfall models take theirs from the GLScene material `voda1`, whose
	// live diffuse is (1, 1, 0.09): blue 0.09, giving 0.09 * 12.0 = 1.08 UV/s, and
	// red/green 1,1 clamping alpha to opaque. gl_Color is clamped to [0,1], so 1.0
	// here would be HROT's ceiling rather than its rate.
	float g_flScrollSpeed < Default( 0.0 ); >;

	// HROT's alpha clamp - the red and green of the same vertex colour whose blue
	// is the flow rate. The water grid pass sets them per water type from cell
	// field 0x09: type 1 is (0.8, 0.91), type 2 (0.55, 0.9). The waterfall
	// material is (1, 1), which is why those surfaces come out exactly opaque -
	// and why the default here is opaque.
	float g_flAlphaMin < Default( 1.0 ); >;
	float g_flAlphaMax < Default( 1.0 ); >;

	// HROT's dist_coords, from the same vertex shader:
	//     dist_coords = gl_MultiTexCoord0.st - vec2(u_time * 0.005 * 5.0)
	// Independent of the vertex colour, so the ripple drifts on still pools too.
	static const float kDistScrollRate = 0.025;

	float4 MainPs( PixelInput i ) : SV_Target0
	{
		Material m = Material::Init();

		float t = g_flTime * kHrotTimeScale;
		float2 uv = i.vTextureCoords.xy;
		float2 tc = uv;

		// (1) scroll, from the vertex shader. Volumes leave g_flScrollSpeed at 0,
		// matching their blue channel.
		tc.y -= t * g_flScrollSpeed;

		// (2) sine wobble, from the fragment shader - always on. HROT scrolls in
		// the vertex stage, so the fragment stage's v_coords is already scrolled
		// and the wobble travels with the flow. Hence tc, not uv.
		float2 u_k = float2( 15.0, -15.0 );
		float2 c = tc * u_k - u_k * 0.5;
		float wobble = sin( ( c.x + c.y + t * 0.5 ) / kWobbleFreq ) * kWobbleAmp;
		tc += wobble;

		// (3) normal-map warp from vodanorm, at HROT's own dist_coords - which
		// scroll on their own, independently of the flow.
		float2 distCoords = uv - t * kDistScrollRate;
		float3 distortion = Tex2DS( g_tDistMap, g_sDist, distCoords * 0.5 ).rgb;
		float3 normal = distortion * 2.0 - 1.0;
		tc += normal.xy * kWarpAmp;

		float4 colour = Tex2DS( g_tColor, g_sSampler0, tc );

		m.Albedo = colour.rgb;
		m.Normal = i.vNormalWs;
		m.Roughness = 1;
		m.Metalness = 0;
		m.AmbientOcclusion = 1;
		m.TintMask = 1;
		// (4) alpha, from the ripple texture ("vlnky" = ripples). HROT:
		//     vlnky = DistMap(dist_coords*2.0).r
		//     a     = clamp( vlnky*1.5 + (1.0 - light.r*1.5), transp.x, transp.y )
		// The light term is HROT's lightmap, which the mount does not port - s&box
		// lights these surfaces itself, so there is no lightmap to sample. Only the
		// ripple term is reproduced. That term is near zero at mid lightmap values
		// (light.r = 2/3), so this matches HROT in ordinary light; HROT's water
		// additionally goes more opaque in shadow and more transparent in bright
		// light. The clamp is what dominates either way.
		float vlnky = Tex2DS( g_tDistMap, g_sDist, distCoords * 2.0 ).r;
		m.Opacity = clamp( vlnky * 1.5, g_flAlphaMin, g_flAlphaMax );
		#if ( S_TRANSLUCENT )
			m.Opacity *= g_flOpacityScale;
		#endif
		m.Emission = 0;
		m.Transmission = 0;

		return ShadingModelStandard::Shade( i, m );
	}
}
