WHOIS_VALID_FIELDS = ['domain', 'email', 'name', 'organization',
                      'address', 'phone', 'nameserver']
WHOIS_SECTIONS = ['admin', 'tech', 'registrant']
WHOIS_SECTION_FIELDS = ['section', 'query', 'city', 'country', 'email', 'name',
                        'organization', 'postalCode', 'state', 'street']
DNS_APPROVED_FIELDS = [
    "lastSeen", "resolve", "firstSeen", "resolveType", "value", "recordType",
    "recordHash", "collected",
]
SSL_VALID_FIELDS = ["issuerSurname", "subjectOrganizationName",
                    "issuerCountry", "issuerOrganizationUnitName",
                    "fingerprint", "subjectOrganizationUnitName",
                    "serialNumber", "subjectEmailAddress",
                    "subjectCountry", "issuerGivenName",
                    "subjectCommonName", "issuerCommonName",
                    "issuerStateOrProvinceName", "issuerProvince",
                    "subjectStateOrProvinceName", "sha1", "sslVersion",
                    "subjectStreetAddress", "subjectSerialNumber",
                    "issuerOrganizationName", "subjectSurname",
                    "subjectLocalityName", "issuerStreetAddress",
                    "issuerLocalityName", "subjectGivenName",
                    "subjectProvince", "issuerSerialNumber",
                    "issuerEmailAddress"]


ATTRIBUTE_APPROVED_FIELDS = [
    "lastSeen", "firstSeen", "attributeType", "hostname", "attributeValue",
]
CLASSIFICATION_VALID_VALUES = ['malicious', 'suspicious', 'non-malicious',
                               'unknown']
ACTIONS = 'actions'
ACTIONS_CLASSIFICATION = 'classification'
ACTIONS_DYNAMIC_DNS = 'dynamic-dns'
ACTIONS_EVER_COMPROMISED = 'ever-compromised'
ACTIONS_MONITOR = 'monitor'
ACTIONS_SINKHOLE = 'sinkhole'
ACTIONS_TAG = 'tags'
ACTIONS_BULK = 'bulk'
ENRICHMENT = 'enrichment'

TRACKER_VALID_FIELDS = ["51laId", "AboutmeId", "AddThisPubId", "AddThisUsername", "AuthorstreamId", "BitbucketcomId", "BitlyId", "CheezburgerId", "ClickyId", "ColourloversId", "DiigoId", "DispusId", "EngadgetId", "EtsyId", "FacebookId", "FavstarId", "FfffoundId", "FlavorsId", "FlickrId", "FoodspottingId", "FreesoundId", "GitHubId", "GithubId", "GoogleAnalyticsTrackingId", "GooglePlusId", "GoogleTagManagerId", "HubpagesId", "ImgurId", "InstagramId", "KloutId", "LanyrdId", "LastfmId", "LibrarythingId", "LinkedInId", "LinkedinId", "MarketinglandcomId", "MixpanelId", "MuckrackId", "MyanimelistId", "MyfitnesspalId", "NewRelicId", "OptimizelyId", "PandoraId", "PicasaId", "PinkbikeId", "PinterestId", "PlancastId", "PlurkId", "PornhubId", "RaptorId", "ReadabilityId", "RedditId", "RedtubeId", "SlideshareId", "SmugmugId", "SmuleId", "SoundcloudId", "SoupId", "SpeakerdeckId", "SporcleId", "StackoverflowId", "SteamcommunityId", "StumbleuponId", "ThesixtyoneId", "TribeId", "TripitId", "TumblrId", "TwitpicId", "TwitterId", "UntappdId", "UstreamId", "WattpadId", "WefollowId", "WhosAmungUsId", "WordPressId", "Wordpress", "SupportId", "XangaId", "Xfire", "SocialId", "XhamsterId", "XvideosId", "YandexMetricaCounterId", "YouTubeChannel", "YouTubeId", "YoutubeId"]