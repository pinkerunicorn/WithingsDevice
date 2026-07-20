<?php
declare(strict_types=1);

class WithingsDevice extends IPSModuleStrict {

    private const MEASURE_WEIGHT = 1;
    private const MEASURE_HEIGHT = 4;
    private const MEASURE_FAT_FREE_MASS = 5;
    private const MEASURE_FAT_RATIO = 6;
    private const MEASURE_FAT_MASS_WEIGHT = 8;
    private const MEASURE_DIASTOLIC_BP = 9;
    private const MEASURE_SYSTOLIC_BP = 10;
    private const MEASURE_HEART_PULSE = 11;
    private const MEASURE_TEMPERATURE = 12;
    private const MEASURE_SP02 = 54;
    private const MEASURE_BODY_TEMPERATURE = 71;
    private const MEASURE_SKIN_TEMPERATURE = 73;
    private const MEASURE_MUSCLE_MASS = 76;
    private const MEASURE_HYDRATION = 77;
    private const MEASURE_BONE_MASS = 88;
    private const MEASURE_PWV = 91;

    public function Create(): void{
        parent::Create();
        
        $this->RegisterPropertyString("ClientID", "");
        $this->RegisterPropertyString("ClientSecret", "");
        $this->RegisterPropertyInteger("FetchInterval", 15);
        $this->RegisterPropertyInteger("LastUpdate", 0);

        // Gemini API-Key und Modell werden zentral über SmartGeminiIO konfiguriert.
        $this->RegisterPropertyInteger("ArchiveDays", 28);
        $this->RegisterPropertyInteger("SMTPInstanceID", 0);
        $this->RegisterPropertyBoolean("EnableAI", false);

        // Versteckte Attribute für OAuth Tokens
        $this->RegisterAttributeString("AccessToken", "");
        $this->RegisterAttributeString("RefreshToken", "");
        $this->RegisterAttributeInteger("TokenExpires", 0);

        $this->RegisterTimer("FetchTimer", 0, 'WITHINGS_FetchMeasurements($_IPS[\'TARGET\']);');

        $this->MaintainVariable("LastMeasurement", "⏱ Letzte Messung", 3, "", 0, true);
        $this->MaintainVariable("DailyReport", "🧠 Gemini Analyse", 3, "", 1, true);
    }

    public function ApplyChanges(): void{
        parent::ApplyChanges();
        // --- Auto-generated References ---
        foreach ($this->GetReferenceList() as $refID) {
            $this->UnregisterReference($refID);
        }
        $ref_SMTPInstanceID = $this->ReadPropertyInteger('SMTPInstanceID');
        if ($ref_SMTPInstanceID > 1 && @IPS_ObjectExists($ref_SMTPInstanceID)) {
            $this->RegisterReference($ref_SMTPInstanceID);
        }
        // ---------------------------------


        
        $this->RegisterHook("/hook/smartwithings");

        $interval = $this->ReadPropertyInteger("FetchInterval");
        $this->SetTimerInterval("FetchTimer", $interval * 60 * 1000);

        $varID = @IPS_GetObjectIDByIdent("LastMeasurement", $this->InstanceID);
        if ($varID !== false) {
            IPS_SetIcon($varID, "Clock");
        }

        $this->UpdatePresentations();
    }

    protected function RegisterHook(string $HookPath): bool {
        $ids = IPS_GetInstanceListByModuleID("{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}");
        if (count($ids) > 0) {
            $hooks = json_decode(IPS_GetProperty($ids[0], "Hooks"), true);
            if (!is_array($hooks)) {
                $hooks = [];
            }
            $found = false;
            foreach ($hooks as $index => $hook) {
                if ($hook['Hook'] == $HookPath) {
                    if ($hook['TargetID'] == $this->InstanceID) {
                        return true;
                    }
                    $hooks[$index]['TargetID'] = $this->InstanceID;
                    $found = true;
                }
            }
            if (!$found) {
                $hooks[] = ['Hook'=> $HookPath, 'TargetID'=> $this->InstanceID];
            }
            IPS_SetProperty($ids[0], "Hooks", json_encode($hooks));
            IPS_ApplyChanges($ids[0]);
        }
        return true;
    }

    private function GetRedirectURI() {
        $cc_ids = IPS_GetInstanceListByModuleID("{9486D575-BE8C-4ED8-B5B5-20930E26DE6F}");
        if (count($cc_ids) > 0) {
            $url = CC_GetConnectURL($cc_ids[0]);
            if ($url != "") {
                return $url . "/hook/smartwithings";
            }
        }
        // Fallback to local IP if Connect is not active
        return "http://". $_SERVER['HTTP_HOST'] . "/hook/smartwithings";
    }

    public function GetAuthURL() {
        $clientId = $this->ReadPropertyString("ClientID");
        if ($clientId == "") {
            echo "Fehler: Client ID ist leer.";
            return;
        }

        $redirectUri = urlencode($this->GetRedirectURI());
        $scope = urlencode("user.metrics,user.info,user.activity");
        $state = md5((string)time());

        $url = "https://account.withings.com/oauth2_user/authorize2?response_type=code&client_id={$clientId}&redirect_uri={$redirectUri}&scope={$scope}&state={$state}";
        
        echo "Bitte öffne diesen Link im Browser, um Symcon mit Withings zu verbinden:\n\n". $url;
    }

    protected function ProcessHookData(): void {
        $this->SendDebug("WebHook", "Daten empfangen: ". print_r($_GET, true), 0);

        if (isset($_GET['code'])) {
            $code = $_GET['code'];
            $this->SendDebug("WebHook", "Auth-Code erhalten: ". $code, 0);

            $clientId = $this->ReadPropertyString("ClientID");
            $clientSecret = $this->ReadPropertyString("ClientSecret");
            $redirectUri = $this->GetRedirectURI();

            $postData = [
                'action'=> 'requesttoken',
                'grant_type'=> 'authorization_code',
                'client_id'=> $clientId,
                'client_secret'=> $clientSecret,
                'code'=> $code,
                'redirect_uri'=> $redirectUri
            ];

            $this->RequestTokens($postData);
            echo "Erfolgreich autorisiert! Du kannst dieses Fenster nun schließen und in Symcon auf 'Daten jetzt manuell abrufen'klicken."; return;
        } else {
            echo "Kein Code empfangen."; return;
        }
    }

    private function RefreshToken() {
        $refreshToken = $this->ReadAttributeString("RefreshToken");
        if ($refreshToken == "") {
            $this->SendDebug("OAuth", "Kein Refresh Token vorhanden. Bitte neu authentifizieren.", 0);
            return false;
        }

        $clientId = $this->ReadPropertyString("ClientID");
        $clientSecret = $this->ReadPropertyString("ClientSecret");

        $postData = [
            'action'=> 'requesttoken',
            'grant_type'=> 'refresh_token',
            'client_id'=> $clientId,
            'client_secret'=> $clientSecret,
            'refresh_token'=> $refreshToken
        ];

        return $this->RequestTokens($postData);
    }

    private function RequestTokens($postData) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://wbsapi.withings.net/v2/oauth2");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        $response = curl_exec($ch);
        if ($response === false) {
            $this->SLog('ERROR', 'API-Anfrage fehlgeschlagen', curl_error($ch));
            curl_close($ch);
            return false;
        }
        curl_close($ch);

        $this->SendDebug("OAuth", "Token Response: ". $response, 0);
        $data = json_decode($response, true);

        if (isset($data['status']) && $data['status'] == 0 && isset($data['body']['access_token'])) {
            $this->WriteAttributeString("AccessToken", $data['body']['access_token']);
            $this->WriteAttributeString("RefreshToken", $data['body']['refresh_token']);
            $this->WriteAttributeInteger("TokenExpires", time() + $data['body']['expires_in'] - 60);
            $this->SendDebug("OAuth", "Tokens erfolgreich gespeichert.", 0);
            return true;
        }

        return false;
    }

    protected function Log(string $text): void
    {
        $this->SLog('INFO', $text);
    }

    public function FetchMeasurements() {
        $accessToken = $this->ReadAttributeString("AccessToken");
        if ($accessToken == "") {
            $this->SLog('ERROR', 'Kein Access Token vorhanden. Bitte autorisieren.');
            $this->SendDebug("Fetch", "Kein Access Token vorhanden.", 0);
            return;
        }

        if (time() > $this->ReadAttributeInteger("TokenExpires")) {
            $this->SendDebug("Fetch", "Token abgelaufen, versuche Refresh...", 0);
            if (!$this->RefreshToken()) {
                $this->SLog('ERROR', 'Token-Refresh fehlgeschlagen!');
                return;
            }
            $accessToken = $this->ReadAttributeString("AccessToken");
        }

        $lastUpdate = $this->ReadPropertyInteger("LastUpdate");
        $highestUpdate = $lastUpdate;
        $highestMeasurementDate = 0;
        $offset = 0;
        $pages = 0;
        $newMeasurements = 0;

        do {
            $postData = [
                'action'=> 'getmeas',
                'lastupdate'=> $lastUpdate
            ];
            if ($offset > 0) {
                $postData['offset'] = $offset;
            }

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, "https://wbsapi.withings.net/measure");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                "Authorization: Bearer ". $accessToken
            ]);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            $response = curl_exec($ch);
            if ($response === false) {
                $this->SLog('ERROR', 'API-Anfrage fehlgeschlagen', curl_error($ch));
                curl_close($ch);
                break;
            }
            curl_close($ch);

            $data = json_decode($response, true);
            if (isset($data['status']) && $data['status'] == 0) {
                if (isset($data['body']['measuregrps']) && is_array($data['body']['measuregrps'])) {
                    foreach ($data['body']['measuregrps'] as $grp) {
                        if (isset($grp['modified'])) {
                            $highestUpdate = max($highestUpdate, $grp['modified']);
                        }
                        $grpDate = isset($grp['date']) ? $grp['date'] : time();
                        if (isset($grp['date'])) {
                            $highestUpdate = max($highestUpdate, $grp['date']);
                            $highestMeasurementDate = max($highestMeasurementDate, $grp['date']);
                        }
                        if (isset($grp['measures']) && is_array($grp['measures'])) {
                            foreach ($grp['measures'] as $measure) {
                                $this->ProcessMeasurement($measure, $grpDate);
                                $newMeasurements++;
                            }
                        }
                    }
                }
                
                $pages++;
                if (isset($data['body']['more']) && $data['body']['more'] == 1 && isset($data['body']['offset'])) {
                    $offset = $data['body']['offset'];
                } else {
                    $offset = 0; // stop
                }

                // Security stop after 50 pages to prevent endless loop / timeout
                if ($pages > 50) {
                    $offset = 0;
                }

            } else {
                $this->SLog('ERROR', 'Fehler beim Abruf der Messwerte.');
                $this->SendDebug("Fetch", "Fehler beim Abruf: ". $response, 0);
                $offset = 0; // stop on error
            }
        } while ($offset > 0);
        
        if ($highestUpdate > $lastUpdate) {
            IPS_SetProperty($this->InstanceID, "LastUpdate", $highestUpdate);
            IPS_ApplyChanges($this->InstanceID); 
        }

        if ($highestMeasurementDate > 0) {
            $currentStr = $this->GetValue("LastMeasurement");
            $currentTs = $currentStr ? strtotime($currentStr) : 0;
            if ($highestMeasurementDate > $currentTs) {
                $this->SetValue("LastMeasurement", date("d.m.Y H:i:s", $highestMeasurementDate));
            }
        }

        if ($newMeasurements > 0) {
            // $this->Log("Abruf erfolgreich. $newMeasurements neue Messwerte verarbeitet.");
            if ($this->ReadPropertyBoolean("EnableAI")) {
                $this->EvaluateWithGemini();
            }
        }
        $this->SendDebug("Fetch", "Abruf erfolgreich beendet (". $pages . "Seiten).", 0);
    }

    private function GetMeasurementConfig($type) {
        $name = "Messwert Typ ". $type;
        $suffix = "";
        $icon = "";

        switch ($type) {
            case self::MEASURE_WEIGHT: $name = "Gewicht"; $suffix = "kg"; $icon = "Scale"; break;
            case self::MEASURE_HEIGHT: $name = "Größe"; $suffix = "m"; $icon = "Distance"; break;
            case self::MEASURE_FAT_FREE_MASS: $name = "Fettfreie Masse"; $suffix = "kg"; $icon = "Scale"; break;
            case self::MEASURE_FAT_RATIO: $name = "Körperfett"; $suffix = "%"; $icon = "Drop"; break;
            case self::MEASURE_FAT_MASS_WEIGHT: $name = "Fettmasse"; $suffix = "kg"; $icon = "Scale"; break;
            case self::MEASURE_DIASTOLIC_BP: $name = "Blutdruck (Diastolisch)"; $suffix = "mmHg"; $icon = "Heart"; break;
            case self::MEASURE_SYSTOLIC_BP: $name = "Blutdruck (Systolisch)"; $suffix = "mmHg"; $icon = "Heart"; break;
            case self::MEASURE_HEART_PULSE: $name = "Herzfrequenz"; $suffix = "bpm"; $icon = "Heart"; break;
            case self::MEASURE_TEMPERATURE: 
            case self::MEASURE_SP02: $name = "SPO2 (Sauerstoffsättigung)"; $suffix = "%"; $icon = "Heart"; break;
            case self::MEASURE_BODY_TEMPERATURE: 
            case self::MEASURE_SKIN_TEMPERATURE: $name = "Temperatur"; $suffix = "°C"; $icon = "Temperature"; break;
            case self::MEASURE_MUSCLE_MASS: $name = "Muskelmasse"; $suffix = "kg"; $icon = "Scale"; break;
            case self::MEASURE_HYDRATION: $name = "Wasseranteil"; $suffix = "kg"; $icon = "Drop"; break;
            case self::MEASURE_BONE_MASS: $name = "Knochenmasse"; $suffix = "kg"; $icon = "Scale"; break;
            case self::MEASURE_PWV: $name = "Pulswellengeschwindigkeit"; $suffix = "m/s"; $icon = "Wind"; break;
            case 123: $name = "VO2 Max"; $suffix = "ml/min/kg"; $icon = "Heart"; break;
            case 130: $name = "Viszeralfett"; $suffix = "%"; $icon = "Drop"; break;
            case 135: 
            case 155: $name = "Gefäßalter"; $suffix = "Jahre"; $icon = "Clock"; break;
            case 136: $name = "Nervenaktivität"; $suffix = "Punkte"; $icon = "Intensity"; break;
            case 138: $name = "QT-Intervall"; $suffix = "ms"; $icon = "Heart"; break;
            case 139: $name = "Vorhofflimmern"; $suffix = ""; $icon = "Heart"; break;
            case 168: $name = "Extrazelluläres Wasser"; $suffix = "kg"; $icon = "Drop"; break;
            case 169: $name = "Intrazelluläres Wasser"; $suffix = "kg"; $icon = "Drop"; break;
            // Body Scan segmented data
            case 170: $name = "Körperfett Rumpf"; $suffix = "%"; $icon = "Drop"; break;
            case 171: $name = "Körperfett Arme"; $suffix = "%"; $icon = "Drop"; break;
            case 172: $name = "Körperfett Beine"; $suffix = "%"; $icon = "Drop"; break;
            case 173: $name = "Fettfreie Masse (Segment)"; $suffix = "kg"; $icon = "Scale"; break;
            case 174: $name = "Fettmasse (Segment)"; $suffix = "kg"; $icon = "Scale"; break;
            case 175: $name = "Muskelmasse (Segment)"; $suffix = "kg"; $icon = "Scale"; break;
            // Newer Body Scan metrics (EDA / Nerve Health)
            case 196: $name = "Nervenaktivität Score"; $suffix = "Punkte"; $icon = "Intensity"; break;
            case 197: $name = "Nervenaktivität (Fuß links)"; $suffix = "Punkte"; $icon = "Intensity"; break;
            case 198: $name = "Nervenaktivität (Fuß rechts)"; $suffix = "Punkte"; $icon = "Intensity"; break;
            case 226: $name = "Grundumsatz (BMR)"; $suffix = "kcal"; $icon = "Flame"; break;
            case 227: $name = "Metabolisches Alter"; $suffix = "Jahre"; $icon = "Clock"; break;
        }

        return [
            'name'=> $name,
            'suffix'=> $suffix,
            'icon'=> $icon
        ];
    }

    private function UpdatePresentations() {
        $children = IPS_GetChildrenIDs($this->InstanceID);
        foreach ($children as $childID) {
            $obj = IPS_GetObject($childID);
            $ident = $obj['ObjectIdent'];
            if (strpos($ident, "Measure_") === 0) {
                $type = (int)substr($ident, 8);
                $config = $this->GetMeasurementConfig($type);
                
                IPS_SetName($childID, $config['name']);
                
                if ($config['suffix'] != "") {
                    IPS_SetVariableCustomPresentation($childID, [
                'PRESENTATION'=> VARIABLE_PRESENTATION_VALUE_PRESENTATION,'SUFFIX'=> ' ' . $config['suffix']]);
                }
                
                if ($config['icon'] != "") {
                    IPS_SetIcon($childID, $config['icon']);
                }
            }
        }
    }

    private function ProcessMeasurement($measure, $timestamp) {
        if (!isset($measure['type']) || !isset($measure['value'])) {
            return;
        }
        $type = $measure['type'];
        $unit = isset($measure['unit']) ? $measure['unit'] : 0;
        $value = $measure['value'] * pow(10, $unit);

        $ident = "Measure_". $type;
        $config = $this->GetMeasurementConfig($type);

        // Variable dynamisch anlegen falls nicht existent
        $identCache =& $this->createdIdents;
        if (!isset($identCache)) {
            $identCache = [];
        }

        if (!isset($identCache[$ident])) {
            $this->MaintainVariable($ident, $config['name'], 2, "", 0, true);
            $varID = @IPS_GetObjectIDByIdent($ident, $this->InstanceID);
            
            if ($varID !== false) {
                $archiveIds = IPS_GetInstanceListByModuleID("{43192F0B-135B-4CE7-A0A7-1475603F3060}");
                if (count($archiveIds) > 0) {
                    @AC_SetLoggingStatus($archiveIds[0], $varID, true);
                    @IPS_ApplyChanges($archiveIds[0]);
                }
                
                if ($config['suffix'] != "") {
                    IPS_SetVariableCustomPresentation($varID, [
                'PRESENTATION'=> VARIABLE_PRESENTATION_VALUE_PRESENTATION,'SUFFIX'=> ' ' . $config['suffix']]);
                }
                
                if ($config['icon'] != "") {
                    IPS_SetIcon($varID, $config['icon']);
                }
            }
            
            $identCache[$ident] = true;
        }

        if (@IPS_GetObjectIDByIdent($ident, $this->InstanceID) !== false) {
            $this->SetValue($ident, $value);
        }
    }

    public function EvaluateWithGemini() {
        // SmartGeminiIO auto-discover
        $geminiInstances = IPS_GetInstanceListByModuleID('{4C8B2A6D-9E3F-4A7B-8C5D-1F6E2A3B7C4D}');
        if (empty($geminiInstances)) {
            $this->SLog('ERROR', 'SmartGeminiIO Instanz nicht gefunden! Bitte eine erstellen.');
            return;
        }
        $geminiId = $geminiInstances[0];

        $archiveIDs = IPS_GetInstanceListByModuleID("{43192F0B-135B-4CE7-A0A7-1475603F3060}");
        if (count($archiveIDs) == 0) {
            $this->SLog('ERROR', 'Kein Archive Control gefunden.');
            return;
        }
        $archiveID = $archiveIDs[0];

        $days = $this->ReadPropertyInteger("ArchiveDays");
        $startTime = time() - ($days * 24 * 60 * 60);
        
        $metrics = [
            self::MEASURE_WEIGHT => "Gewicht (kg)",
            self::MEASURE_FAT_RATIO => "Körperfett (%)",
            self::MEASURE_HEART_PULSE => "Herzfrequenz (bpm)",
            self::MEASURE_DIASTOLIC_BP => "Blutdruck diastolisch (mmHg)",
            self::MEASURE_SYSTOLIC_BP => "Blutdruck systolisch (mmHg)",
            self::MEASURE_MUSCLE_MASS => "Muskelmasse (kg)",
            self::MEASURE_HYDRATION => "Wasseranteil (kg)"
        ];

        $prompt = "Du bist ein motivierender KI-Gesundheits-Coach. Hier sind meine aufgezeichneten Gesundheitsdaten der letzten ". $days . "Tage.\n";
        $prompt .= "Bitte bewerte den Trend der Messwerte, gib mir ein kurzes Feedback und weise auf Besonderheiten hin (z.B. stark steigender Blutdruck oder Gewichtsverlust).\n";
        $prompt .= "Fasse dich kurz, bleibe positiv und präzise. Antworte in Deutsch und formatiere den Text in einfachem Markdown.\n\n";

        $hasData = false;
        foreach ($metrics as $type => $label) {
            $ident = "Measure_". $type;
            $varID = @IPS_GetObjectIDByIdent($ident, $this->InstanceID);
            if ($varID !== false && AC_GetLoggingStatus($archiveID, $varID)) {
                $values = AC_GetLoggedValues($archiveID, $varID, $startTime, time(), 0);
                if (count($values) > 0) {
                    $prompt .= "### $label\n";
                    $aggregates = AC_GetAggregatedValues($archiveID, $varID, 1, $startTime, time(), 0);
                    $aggregates = array_reverse($aggregates);
                    foreach ($aggregates as $agg) {
                        if ($agg['Duration'] > 0) {
                            $dateStr = date("d.m.", $agg['TimeStamp']);
                            $valStr = number_format($agg['Avg'], 1);
                            $prompt .= "- $dateStr: $valStr\n";
                            $hasData = true;
                        }
                    }
                    $prompt .= "\n";
                }
            }
        }

        if (!$hasData) {
            $this->SLog('WARNING', 'Keine Archivdaten für Gemini Auswertung gefunden.');
            return;
        }

        $instanceId = $this->InstanceID;

        // Async — kein Schema = freier Markdown-Text, Temperatur 0.4
        $script = '<?php
            $result = GIO_Query(' . $geminiId . ',
                ' . var_export($prompt, true) . ',
                \'Du bist ein motivierender KI-Gesundheits-Coach. Antworte auf Deutsch im Markdown-Format.\',
                \'\',
                0.4
            );
            WITHINGS_ProcessGeminiResult(' . $instanceId . ', $result);
        ';
        IPS_RunScriptText($script);
    }

    public function ProcessGeminiResult(string $report) {
        if (empty($report)) {
            $this->SLog('ERROR', 'SmartGeminiIO lieferte keine Antwort.');
            return;
        }

        $this->SetValue('DailyReport', $report);
        $this->SLog('INFO', 'Gemini Gesundheitsbericht erfolgreich generiert.');

        $smtpID = $this->ReadPropertyInteger('SMTPInstanceID');
        if ($smtpID > 0 && IPS_InstanceExists($smtpID)) {
            @SMTP_SendMail($smtpID, 'Dein Gesundheits-Coach Update', $report);
        }
    }

    private function SLog(string $level, string $message, string $details = ''): void
    {
        $source = static::class;
        $slogInstances = @IPS_GetInstanceListByModuleID('{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}');
        if (is_array($slogInstances) && count($slogInstances) > 0) {
            @SLOG_Log($slogInstances[0], $level, $source, $message, $details);
        } else {
            IPS_LogMessage('SmartVillaKunterbunt', $source . ': ' . $message);
        }
    }

    protected function LogMessage(string $Message, int $Type): bool
    {
        $this->SLog('INFO', $Message);
        IPS_LogMessage('SmartVillaKunterbunt', 'WithingsDevice: '. $Message);
        return true;
    }

    public function GetConfigurationForm(): string
    {
        return <<<'EOT'
{
    "elements": [
        {
            "type": "Label",
            "caption": "1. Withings API Zugangsdaten"
        },
        {
            "type": "Label",
            "caption": "Hier trägst du die Client ID und das Client Secret aus deinem Withings Developer Account ein. Diese Daten brauchst du, damit sich Symcon mit deinem Withings Account verbinden kann."
        },
        {
            "type": "RowLayout",
            "items": [
                {
                    "type": "ValidationTextBox",
                    "name": "ClientID",
                    "caption": "Client ID"
                }
            ]
        },
        {
            "type": "PasswordTextBox",
            "name": "ClientSecret",
            "caption": "Client Secret"
        },
        {
            "type": "Label",
            "caption": "WICHTIG: Die Callback-URL in deinem Withings Developer Account MUSS exakt so lauten:"
        },
        {
            "type": "Label",
            "caption": "https://<DEINE-CONNECT-ID>.ipmagic.de/hook/smartwithings"
        },
        {
            "type": "Label",
            "caption": "2. Einstellungen"
        },
        {
            "type": "Label",
            "caption": "Gib hier an, wie oft deine Daten von Withings abgerufen werden sollen. Wenn du 0 einträgst, wird der automatische Abruf deaktiviert."
        },
        {
            "type": "NumberSpinner",
            "name": "FetchInterval",
            "caption": "Abruf-Intervall (in Minuten, 0 = deaktiviert)",
            "minimum": 0,
            "maximum": 1440
        },
        {
            "type": "Label",
            "caption": "3. KI Auswertung (Google Gemini)"
        },
        {
            "type": "Label",
            "caption": "Hier kannst du deinen persönlichen KI-Coach aktivieren. Du brauchst dafür einen API Key von Google. Gib außerdem an, über welchen Zeitraum die Trends berechnet werden sollen und wohin dir der Bericht geschickt werden darf."
        },
        {
            "type": "CheckBox",
            "name": "EnableAI",
            "caption": "Gemini Auswertung nach jedem Abruf aktivieren"
        },
        {
            "type": "Label",
            "caption": "API-Key und Modell werden zentral über die 'Smart Gemini IO' Instanz konfiguriert.\nBitte dort einmalig deinen Google Gemini API-Key hinterlegen."
        },
        {
            "type": "NumberSpinner",
            "name": "ArchiveDays",
            "caption": "Trend-Zeitraum (Tage, 28 = 4 Wochen)",
            "minimum": 1,
            "maximum": 365
        },
        {
            "type": "SelectInstance",
            "name": "SMTPInstanceID",
            "caption": "SMTP Instanz für täglichen Bericht per Mail"
        }
    ],
    "actions": [
        {
            "type": "Button",
            "label": "Mit Withings verbinden (OAuth Login)",
            "onClick": "echo WITHINGS_GetAuthURL($id);"
        },
        {
            "type": "Button",
            "label": "Daten jetzt manuell abrufen",
            "onClick": "WITHINGS_FetchMeasurements($id);"
        },
        {
            "type": "Button",
            "label": "KI Auswertung (inkl. Mail) jetzt testen",
            "onClick": "WITHINGS_EvaluateWithGemini($id);"
        }
    ]
}
EOT;
    }
}


?>
