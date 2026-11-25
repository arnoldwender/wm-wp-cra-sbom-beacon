( function ( wp ) {
	if ( ! wp || ! wp.blocks || ! wp.element || ! wp.blockEditor || ! wp.components || ! wp.i18n ) {
		return;
	}

	var registerBlockType = wp.blocks.registerBlockType;
	var el = wp.element.createElement;
	var Fragment = wp.element.Fragment;
	var useBlockProps = wp.blockEditor.useBlockProps;
	var InspectorControls = wp.blockEditor.InspectorControls;
	var PanelBody = wp.components.PanelBody;
	var ToggleControl = wp.components.ToggleControl;
	var __ = wp.i18n.__;
	var ServerSideRender = wp.serverSideRender;

	registerBlockType( 'wm/cra-psirt', {
		title: __( 'CRA Beacon: PSIRT & Sicherheitshinweise', 'wm-cra-sbom-beacon' ),
		description: __( 'Zeigt den Sicherheitskontakt nach RFC 9116, Links zu SBOM und CSAF-Index sowie veröffentlichte Sicherheitshinweise.', 'wm-cra-sbom-beacon' ),
		category: 'widgets',
		icon: 'shield',
		attributes: {
			showJsonLinks: {
				type: 'boolean',
				default: true,
			},
			showAdvisories: {
				type: 'boolean',
				default: true,
			},
		},
		supports: {
			html: false,
			align: [ 'wide', 'full' ],
		},
		edit: function ( props ) {
			var attributes = props.attributes;
			var setAttributes = props.setAttributes;
			var blockProps = useBlockProps();

			return el(
				Fragment,
				null,
				el(
					InspectorControls,
					null,
					el(
						PanelBody,
						{
							title: __( 'Darstellung', 'wm-cra-sbom-beacon' ),
							initialOpen: true,
						},
						el( ToggleControl, {
							label: __( 'JSON-Verweise anzeigen (SBOM & CSAF)', 'wm-cra-sbom-beacon' ),
							checked: false !== attributes.showJsonLinks,
							onChange: function ( value ) {
								setAttributes( { showJsonLinks: !! value } );
							},
						} ),
						el( ToggleControl, {
							label: __( 'Veröffentlichte Sicherheitshinweise anzeigen', 'wm-cra-sbom-beacon' ),
							checked: false !== attributes.showAdvisories,
							onChange: function ( value ) {
								setAttributes( { showAdvisories: !! value } );
							},
						} )
					)
				),
				el(
					'div',
					blockProps,
					ServerSideRender
						? el( ServerSideRender, {
								block: 'wm/cra-psirt',
								attributes: attributes,
						  } )
						: el( 'p', null, __( 'CRA Beacon: PSIRT & Sicherheitshinweise', 'wm-cra-sbom-beacon' ) )
				)
			);
		},
		save: function () {
			return null;
		},
	} );
} )( window.wp );
