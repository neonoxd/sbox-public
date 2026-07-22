namespace Sandbox;

/// <summary>
/// Plays vertex animation held as morph targets, where each frame is a morph
/// named <c>&lt;sequence&gt;&lt;number&gt;</c> - <c>run1</c>..<c>run17</c>.
/// </summary>
/// <remarks>
/// Morphs are normally a face: visemes driven by the voice components, or blend
/// shapes authored into a <c>.vmdl</c>. This drives them as animation
/// instead, which is what a model converted from a vertex-animated format -
/// Quake's MD2 and its descendants - arrives as. Such a model has no skeleton
/// and no animation graph, so nothing else here can play it.
///
/// Sequences are recovered from the morph names by splitting off the trailing
/// digits, so a model carries its own sequence table and nothing needs to be
/// configured per model.
///
/// Interpolation is two weights: frame N at <c>1-t</c> and frame N+1 at
/// <c>t</c>. Morph deltas are linear and measured from the mesh, so that sum is
/// exactly the lerp between the two frames - no shader work involved. A frame
/// whose morph displaces nothing is the rest pose, and weighting it does
/// nothing, which is also correct.
/// </remarks>
[Title( "Morph Animator" )]
[Category( "Rendering" )]
[Icon( "animation" )]
public sealed class MorphAnimator : Component, Component.ExecuteInEditor
{
	/// <summary>
	/// The renderer to pose. Defaults to one on this object.
	/// </summary>
	[Property]
	public SkinnedModelRenderer Renderer
	{
		get => _renderer;
		set
		{
			if ( _renderer == value ) return;

			// Released through the old renderer, before it is let go of - the
			// weights are held there, and reassigning first would strand the
			// current frame on it permanently.
			ClearApplied();

			_renderer = value;
			Configure();
		}
	}
	SkinnedModelRenderer _renderer;

	/// <summary>
	/// Which sequence to play, from those the model's morph names imply.
	/// </summary>
	[Property, Editor( "MorphSequence" )]
	public string Sequence
	{
		get => _sequence;
		set
		{
			if ( _sequence == value ) return;

			_sequence = value;
			_time = 0.0f;

			// The morphs the old sequence left set are not part of the new one
			// and nothing else will clear them, so the first pose of the new
			// sequence would be laid on top of the last pose of the old.
			ClearApplied();
		}
	}
	string _sequence;

	/// <summary>
	/// Advance the animation. When false the current frame is still applied, so
	/// scrubbing <see cref="Time"/> poses the model.
	/// </summary>
	[Property] public bool Playing { get; set; } = true;

	/// <summary>
	/// Restart at the end rather than holding the last frame.
	/// </summary>
	[Property] public bool Loop { get; set; } = true;

	/// <summary>
	/// Frames per second. MD2-era content is usually authored around 10.
	/// </summary>
	[Property, Range( 0.0f, 60.0f )] public float FrameRate { get; set; } = 10.0f;

	/// <summary>
	/// Blend between frames. Off gives the snap of the original hardware.
	/// </summary>
	[Property] public bool Interpolate { get; set; } = true;

	/// <summary>
	/// Playback rate multiplier.
	/// </summary>
	[Property, Range( 0.0f, 4.0f )] public float Speed { get; set; } = 1.0f;

	/// <summary>
	/// Seconds into the current sequence.
	/// </summary>
	public float Time
	{
		get => _time;
		set => _time = value;
	}
	float _time;

	/// <summary>
	/// True when a non-looping sequence has reached its last frame.
	/// </summary>
	public bool IsFinished { get; private set; }

	/// <summary>
	/// The sequences this model has, in name order.
	/// </summary>
	public IReadOnlyList<string> SequenceNames
	{
		get
		{
			EnsureSequences();
			return _names;
		}
	}

	/// <summary>
	/// The frames of <see cref="Sequence"/>, in playback order.
	/// </summary>
	public IReadOnlyList<string> Frames
	{
		get
		{
			EnsureSequences();
			return _sequence is not null && _sequences.TryGetValue( _sequence, out var frames )
				? frames
				: [];
		}
	}

	Dictionary<string, string[]> _sequences = new( StringComparer.OrdinalIgnoreCase );
	string[] _names = [];
	Model _builtFrom;

	// The morphs currently held at a non-zero weight. Kept so they can be
	// released: the accessor holds every weight ever set until it is cleared,
	// so a frame left behind stays mixed into every later pose.
	string _appliedA;
	string _appliedB;

	protected override void OnEnabled()
	{
		Renderer ??= GetComponent<SkinnedModelRenderer>();

		Configure();
	}

	/// <summary>
	/// Prepares whichever renderer is currently assigned.
	/// </summary>
	void Configure()
	{
		// Nothing else drives these models, and an animation graph on a model
		// that has none still overwrites the pose we set.
		if ( Renderer.IsValid() )
			Renderer.UseAnimGraph = false;

		EnsureSequences();

		// A component dropped onto a model is more useful playing something than
		// playing nothing, and every model here has at least one sequence.
		if ( string.IsNullOrEmpty( _sequence ) && _names.Length > 0 )
			_sequence = _names[0];
	}

	protected override void OnDisabled()
	{
		ClearApplied();
	}

	protected override void OnUpdate()
	{
		if ( !Renderer.IsValid() )
			return;

		EnsureSequences();

		var frames = Frames;
		if ( frames.Count == 0 )
			return;

		if ( Playing )
			_time += Sandbox.Time.Delta * Speed;

		Apply( frames );
	}

	void Apply( IReadOnlyList<string> frames )
	{
		var position = _time * FrameRate;
		IsFinished = false;

		if ( Loop )
		{
			// Wraps across the whole sequence rather than at the last frame, so
			// the final frame blends back into the first instead of snapping.
			position -= MathF.Floor( position / frames.Count ) * frames.Count;
		}
		else if ( position >= frames.Count - 1 )
		{
			position = frames.Count - 1;
			IsFinished = true;
		}

		var index = (int)MathF.Floor( position );
		var fraction = position - index;

		index = Math.Clamp( index, 0, frames.Count - 1 );
		var next = Loop ? (index + 1) % frames.Count : Math.Min( index + 1, frames.Count - 1 );

		if ( !Interpolate )
		{
			fraction = 0.0f;
			next = index;
		}

		Set( frames[index], 1.0f - fraction, frames[next], fraction );
	}

	/// <summary>
	/// Holds exactly the two named morphs, releasing whatever was held before.
	/// </summary>
	void Set( string a, float weightA, string b, float weightB )
	{
		if ( _appliedA is not null && _appliedA != a && _appliedA != b )
			Renderer.Morphs.Clear( _appliedA );

		if ( _appliedB is not null && _appliedB != a && _appliedB != b )
			Renderer.Morphs.Clear( _appliedB );

		// Zero fade time: the accessor's default blends towards a new weight
		// over time, which on a per-frame update means the pose always trails
		// the frame it is meant to be showing.
		Renderer.Morphs.Set( a, weightA, 0.0f );

		if ( b != a )
			Renderer.Morphs.Set( b, weightB, 0.0f );

		_appliedA = a;
		_appliedB = b;
	}

	void ClearApplied()
	{
		if ( !Renderer.IsValid() )
			return;

		if ( _appliedA is not null ) Renderer.Morphs.Clear( _appliedA );
		if ( _appliedB is not null ) Renderer.Morphs.Clear( _appliedB );

		_appliedA = null;
		_appliedB = null;
	}

	void EnsureSequences()
	{
		var model = Renderer.IsValid() ? Renderer.Model : null;
		if ( model == _builtFrom )
			return;

		_builtFrom = model;
		_sequences = BuildSequences( model?.Morphs?.Names ?? [] );
		_names = [.. _sequences.Keys.Order( StringComparer.OrdinalIgnoreCase )];
	}

	/// <summary>
	/// Groups morph names into sequences by their trailing digits, ordering the
	/// frames of each numerically.
	/// </summary>
	/// <remarks>
	/// Numeric rather than alphabetical because <c>run10</c> sorts before
	/// <c>run2</c> as text, which would play the animation in a scrambled order
	/// that still looks like animation - the kind of wrong that survives being
	/// looked at.
	///
	/// The name order this receives is not relied upon: <c>Model.Morphs.Names</c>
	/// comes out of a dictionary, and its order is an implementation detail
	/// rather than a promise about frame order.
	/// </remarks>
	public static Dictionary<string, string[]> BuildSequences( IReadOnlyList<string> morphNames )
	{
		var grouped = new Dictionary<string, List<(string Name, int Number)>>( StringComparer.OrdinalIgnoreCase );

		foreach ( var name in morphNames )
		{
			if ( string.IsNullOrWhiteSpace( name ) )
				continue;

			var end = name.Length;
			while ( end > 0 && char.IsAsciiDigit( name[end - 1] ) )
				end--;

			// An unnumbered morph is its own single-frame sequence. That covers
			// a model whose morphs really are blend shapes, which should still
			// be selectable rather than silently dropped.
			var stem = end > 0 ? name[..end] : name;
			var number = end < name.Length && int.TryParse( name[end..], out var parsed ) ? parsed : 0;

			if ( !grouped.TryGetValue( stem, out var frames ) )
				grouped[stem] = frames = [];

			frames.Add( (name, number) );
		}

		var result = new Dictionary<string, string[]>( StringComparer.OrdinalIgnoreCase );
		foreach ( var (stem, frames) in grouped )
		{
			frames.Sort( ( a, b ) => a.Number.CompareTo( b.Number ) );
			result[stem] = [.. frames.Select( x => x.Name )];
		}

		return result;
	}
}
