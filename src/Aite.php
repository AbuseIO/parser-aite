<?php

namespace AbuseIO\Parsers;

use AbuseIO\Models\Incident;

/**
 * Class Aite
 * @package AbuseIO\Parsers
 */
class Aite extends Parser
{
    /**
     * Create a new Aite instance
     *
     * @param \PhpMimeMailParser\Parser $parsedMail phpMimeParser object
     * @param array $arfMail array with ARF detected results
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     * @return array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        // Validate user based regex
        try {
            preg_match(
                config("{$this->configBase}.parser.file_regex"),
                '',
                $matches
            );

        } catch (\Exception $e) {
            $this->warningCount++;

            return $this->failed('Configuration error in the regular expression');
        }

        foreach ($this->parsedMail->getAttachments() as $attachment) {
            if (strpos($attachment->filename, '.gz') !== false
                && $attachment->contentType == 'application/octet-stream'
            ) {
                $report = json_decode(gzdecode($attachment->getContent()), true);

                if (json_last_error() === JSON_ERROR_NONE) {

                    $this->feedName = 'THREAT_ALERT';

                    // If feed is known and enabled, validate data and save report
                    if ($this->isKnownFeed() && $this->isEnabledFeed()) {

                        // Handle field mappings first
                        $aliasses = config("{$this->configBase}.feeds.{$this->feedName}.aliasses");
                        if (is_array($aliasses)) {
                            foreach ($aliasses as $alias => $real) {
                                if (array_key_exists($alias, $report)) {
                                    $report[$real] = $report[$alias];
                                    unset($report[$alias]);
                                }
                            }
                        }

                        // Sanity check
                        if ($this->hasRequiredFields($report) === true) {
                            // incident has all requirements met, filter and add!
                            $report = $this->applyFilters($report);

                            $incident = new Incident();
                            $incident->source      = $report['owner']['name'];
                            $incident->source_id   = $report['id'];
                            $incident->class       = config("{$this->configBase}.feeds.{$this->feedName}.class");
                            $incident->type        = config("{$this->configBase}.feeds.{$this->feedName}.type");
                            $incident->timestamp   = strtotime($report['last_updated']);
                            $incident->information = json_encode([
                                
                            ]);

                            switch($report['type']) {
                                case 'URI':
                                    $incident->ip          = $report['enrichments']['domain_address'];
                                    $incident->domain      = $report['enrichments']['domain_name'];
                                    break;
                                case 'IP_ADDRESS':
                                    $incident->ip          = $report['raw_indicator'];
                                    break;

                            }

                            //unset($report['enrichments']);
                            unset($report['owner']);
                            $incident->information = json_encode($report);

                            $this->incidents[] = $incident;

                        } //End hasRequired fields

                    } // End isKnown & isEnabled

                } else { // Pregmatch failed to get feedName from attachment
                    $this->warningCount++;
                }

            } else { // Attached file is not a CSV within a ZIP file
                $this->warningCount++;
            }

        } // End foreach attachment loop

        return $this->success();
    }
}
