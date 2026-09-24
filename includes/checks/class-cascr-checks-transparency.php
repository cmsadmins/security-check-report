<?php
/**
 * Checks for transparency and labelling obligations.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Transparency and disclosure checks.
 *
 * These read local state only. Nothing here talks to a remote service, and
 * nothing here judges the content itself: whether a site publishes AI output
 * cannot be read from the database, only whether it is prepared to say so.
 */
class CASCR_Checks_Transparency extends CASCR_Checks_Base {

	/**
	 * Is AI-generated content on this site labelled?
	 *
	 * The obligation applies to sites that publish AI output or run a chatbot,
	 * and this check cannot tell those apart from the rest. That is why it
	 * warns rather than fails and carries a small weight: an installation with
	 * no AI content anywhere still reads this, and its grade must survive it.
	 *
	 * @return array
	 */
	public static function ai_content_disclosure() {
		$active     = self::active_from_map( 'ai_disclosure_plugins' );
		$configured = array();

		foreach ( $active as $name => $options ) {
			foreach ( $options as $option ) {
				// A folder on disk says someone meant to do this. The settings
				// the plugin writes say someone finished it, which is the only
				// half that puts a label in front of a visitor.
				if ( null !== get_option( $option, null ) ) {
					$configured[] = $name;
					break;
				}
			}
		}

		if ( ! empty( $configured ) ) {
			return CASCR_Result::pass(
				__( 'AI-generated content is labelled and visitors are told when they reach an AI system.', 'security-check-report' ),
				$configured
			);
		}

		if ( ! empty( $active ) ) {
			return CASCR_Result::warn(
				__( 'A disclosure plugin is active but was never set up, so nothing is labelled yet.', 'security-check-report' ),
				4,
				array_keys( $active ),
				__( 'Open the plugin settings and switch the labelling on. Until that is saved the plugin changes nothing a visitor can see.', 'security-check-report' ),
				self::transparai_link()
			);
		}

		return CASCR_Result::warn(
			__( 'Since 2 August 2026, Article 50 of the EU AI Act asks for a machine-readable label on AI-generated content and for a notice when visitors are talking to an AI system. No solution for that is active on this installation.', 'security-check-report' ),
			4,
			array(),
			__( 'If the site publishes AI-generated text, images or video, or runs a chatbot, install one of the disclosure plugins from the directory and switch the labelling on. EU AI Label and EU AI Act Ready are free and cover media labels and a visitor notice. TransparAI, which we build ourselves, puts media labels, text marking and chatbot disclosure in one place; it is named here because it fits, not because you need it.', 'security-check-report' ),
			self::transparai_link()
		);
	}

	/**
	 * Our own plugin, offered as one option among others.
	 *
	 * Named openly as ours in the remediation text above, so a reader can weigh
	 * the recommendation for what it is. The free alternatives are named first.
	 *
	 * @return array
	 */
	private static function transparai_link() {
		return array(
			'url'   => 'https://wordpress.org/plugins/transparai/',
			'label' => __( 'TransparAI, our own plugin for AI content disclosure', 'security-check-report' ),
		);
	}
}
