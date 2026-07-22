
namespace Editor;

/// <summary>
/// Picks a sequence from those the target's model actually has.
/// </summary>
/// <remarks>
/// The list is per model and only exists at runtime - it is recovered from
/// morph names rather than declared anywhere - so it cannot be an enum, and a
/// list property on the component would serialize a copy of it into every scene
/// that used one.
///
/// Read through <c>TypeLibrary</c> rather than by referencing the component:
/// this editor library cannot see the game addon the component lives in. The
/// alternative was to regroup the morph names here, which would put the same
/// rule in two places and let the dropdown and the playback disagree about what
/// a sequence is.
/// </remarks>
[CustomEditor( typeof( string ), NamedEditor = "MorphSequence" )]
file class MorphSequenceControlWidget : ControlWidget
{
	public override bool SupportsMultiEdit => true;

	public MorphSequenceControlWidget( SerializedProperty property ) : base( property )
	{
		Layout = Layout.Row();

		Rebuild();
	}

	void Rebuild()
	{
		Layout.Clear( true );

		var names = SequenceNames();
		if ( names.Length == 0 )
		{
			// A model with no morphs at all is a normal thing to have selected -
			// distinct from one whose sequence no longer resolves, below.
			Layout.Add( new Label( "None" ) );
			return;
		}

		var comboBox = new ComboBox( this );
		var current = SerializedProperty.GetValue<string>();

		comboBox.AddItem(
			string.Empty,
			onSelected: () => Select( null ),
			selected: string.IsNullOrEmpty( current ) );

		foreach ( var name in names )
		{
			comboBox.AddItem(
				name,
				onSelected: () => Select( name ),
				selected: string.Equals( current, name, StringComparison.OrdinalIgnoreCase )
					&& !SerializedProperty.IsMultipleDifferentValues );
		}

		// A saved sequence the model no longer has would otherwise not appear in
		// the list, so the control would read as "nothing selected" and the next
		// edit would quietly discard a setting that is only wrong because the
		// wrong model is assigned.
		if ( !string.IsNullOrEmpty( current ) &&
			 !names.Contains( current, StringComparer.OrdinalIgnoreCase ) )
		{
			comboBox.AddItem(
				$"{current} (missing)",
				onSelected: () => Select( current ),
				selected: true );
		}

		Layout.Add( comboBox );
	}

	void Select( string name )
	{
		PropertyStartEdit();
		SerializedProperty.SetValue( name );
		PropertyFinishEdit();
	}

	/// <summary>
	/// The sequences available across every selected target.
	/// </summary>
	/// <remarks>
	/// The union rather than the intersection: these components are usually
	/// selected together while pointing at different models, and offering only
	/// what they share would leave the list empty exactly when it is most useful.
	/// </remarks>
	string[] SequenceNames()
	{
		return SerializedProperty.Parent.Targets
			.SelectMany( SequenceNamesOf )
			.Distinct( StringComparer.OrdinalIgnoreCase )
			.Order( StringComparer.OrdinalIgnoreCase )
			.ToArray();
	}

	static IEnumerable<string> SequenceNamesOf( object target )
	{
		if ( target is null )
			return [];

		var type = Sandbox.Game.TypeLibrary?.GetType( target.GetType() );
		var value = type?.GetProperty( "SequenceNames" )?.GetValue( target );

		return value as IEnumerable<string> ?? [];
	}

	protected override void OnValueChanged()
	{
		Rebuild();
	}

	/// <summary>
	/// Includes the available sequences, not just the selected one, so assigning
	/// a different model rebuilds the list instead of leaving the previous
	/// model's sequences on offer.
	/// </summary>
	protected override int ValueHash
	{
		get
		{
			var hash = new HashCode();
			hash.Add( base.ValueHash );

			foreach ( var name in SequenceNames() )
				hash.Add( name );

			return hash.ToHashCode();
		}
	}
}
