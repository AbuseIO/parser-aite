<?php

return [
    'parser' => [
        'name'          => 'Aite',
        'enabled'       => true,
        'file_regex'    => "~report\.json\.gz~i",
        'sender_map'    => [
            '/cert@abuse.io/',
        ],
        'body_map'      => [
            //
        ],
    ],


    'feeds' => [
         'THREAT_ALERT' => [
             'class'     => 'THREAT_ALERT',
             'type'      => 'ABUSE',
             'enabled'   => true,
             'fields'    => [
                 'confidence',
                 'id',
                 'last_updated',
                 'precision',
                 'privacy_type',
                 'review_status',
                 'severity',
                 'share_level',
                 'status',
                 'type',
             ],


             // Fiels you want to have removed from the event, before passing it along.
             'filters'   => [
                 'owner.email',
                 'owner.name',
                 'privacy_type',
             ],

             // By default all events are _excluded_ and not processed. By using requirements (single values)
             // and selections (multiple values) you can create a match on the events you want to process. The
             // selections are used first in an OR statement, so BGPcounty=NL OR cctld=NL.
             // After selections have been made each selection is passed along towards the requirements in an
             // AND selection, so selected events should have a confidence>50 (higher then 50) and expired
             // days=0.
             'requirements' => [
                 // Minimal confidence level from the event (0-100)
                 'confidence' => '>50',
                 // Number of days after experation we still want to process the event (positive number)
                 'expired_days' => '0',
             ],

             'selections' => [
                 'enrichments.ip_bgpcountry' 	=> [
                     'NL',
                 ],
                 'enrichments.domain_cctld'     => [
                    'NL',
                 ],
             ],

             'exclusions' => [

             ],
         ],

    ],
];
