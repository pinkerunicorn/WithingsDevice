<?php
declare(strict_types=1);

class WithingsDevice extends IPSModuleStrict {

    public function Create(): void{
        parent::Create();
        
        $this->RegisterPropertyString("ClientID", "");
        $this->RegisterPropertyString("ClientSecret", "");
        $this->RegisterPropertyInteger("FetchInterval", 15);
        $this->RegisterPropertyInteger("LastUpdate", 0);

        // AI Properties
        $this->RegisterPropertyBoolean("EnableAI", false);
        $this->RegisterPropertyString("GeminiApiKey", "");
        $this->RegisterPropertyString("GeminiModel", "gemini-3.5-flash");
        $this->RegisterPropertyInteger("ArchiveDays", 28);
        $this->RegisterPropertyInteger("SMTPInstanceID", 0);

        // Versteckte Attribute für OAuth Tokens
        $this->RegisterAttributeString("AccessToken", "");
        $this->RegisterAttributeString("RefreshToken", "");
        $this->RegisterAttributeInteger("TokenExpires", 0);

        $this->RegisterTimer("FetchTimer", 0, 'WITHINGS_FetchMeasurements($_IPS[\'TARGET\']);');

        $this->MaintainVariable("LastMeasurement", "⏱️ Letzte Messung", 3, "", 0, true);
        $this->MaintainVariable("DailyReport", "🧠 Gemini Analyse", 3, "", 1, true);
    }

    public function ApplyChanges(): void{
        parent::ApplyChanges();
        
        $this->RegisterHook("/hook/withings");

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
                $hooks[] = ['Hook' => $HookPath, 'TargetID' => $this->InstanceID];
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
                return $url . "/hook/withings";
            }
        }
        // Fallback to local IP if Connect is not active
        return "http://" . $_SERVER['HTTP_HOST'] . "/hook/withings";
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
        
        echo "Bitte öffne diesen Link im Browser, um Symcon mit Withings zu verbinden:\n\n" . $url;
    }

    protected function ProcessHookData(): void {
        $this->SendDebug("WebHook", "Daten empfangen: " . print_r($_GET, true), 0);

        if (isset($_GET['code'])) {
            $code = $_GET['code'];
            $this->SendDebug("WebHook", "Auth-Code erhalten: " . $code, 0);

            $clientId = $this->ReadPropertyString("ClientID");
            $clientSecret = $this->ReadPropertyString("ClientSecret");
            $redirectUri = $this->GetRedirectURI();

            $postData = [
                'action' => 'requesttoken',
                'grant_type' => 'authorization_code',
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'code' => $code,
                'redirect_uri' => $redirectUri
            ];

            $this->RequestTokens($postData);
            echo "Erfolgreich autorisiert! Du kannst dieses Fenster nun schließen und in Symcon auf 'Daten jetzt manuell abrufen' klicken."; return;
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
            'action' => 'requesttoken',
            'grant_type' => 'refresh_token',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'refresh_token' => $refreshToken
        ];

        return $this->RequestTokens($postData);
    }

    private function RequestTokens($postData) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://wbsapi.withings.net/v2/oauth2");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
        $response = curl_exec($ch);
        curl_close($ch);

        $this->SendDebug("OAuth", "Token Response: " . $response, 0);
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
        IPS_LogMessage('SmartVillaKunterbunt', 'WithingsDevice: ' . $text);
    }

    public function FetchMeasurements() {
        $accessToken = $this->ReadAttributeString("AccessToken");
        if ($accessToken == "") {
            $this->Log("Kein Access Token vorhanden. Bitte autorisieren.");
            $this->SendDebug("Fetch", "Kein Access Token vorhanden.", 0);
            return;
        }

        if (time() > $this->ReadAttributeInteger("TokenExpires")) {
            $this->SendDebug("Fetch", "Token abgelaufen, versuche Refresh...", 0);
            if (!$this->RefreshToken()) {
                $this->Log("Token-Refresh fehlgeschlagen!");
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
                'action' => 'getmeas',
                'lastupdate' => $lastUpdate
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
                "Authorization: Bearer " . $accessToken
            ]);
            $response = curl_exec($ch);
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
                $this->Log("Fehler beim Abruf der Messwerte.");
                $this->SendDebug("Fetch", "Fehler beim Abruf: " . $response, 0);
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
            $this->Log("Abruf erfolgreich. $newMeasurements neue Messwerte verarbeitet.");
            if ($this->ReadPropertyBoolean("EnableAI")) {
                $this->EvaluateWithGemini();
            }
        }
        $this->SendDebug("Fetch", "Abruf erfolgreich beendet (" . $pages . " Seiten).", 0);
    }

    private function GetMeasurementConfig($type) {
        $name = "Messwert Typ " . $type;
        $suffix = "";
        $icon = "";

        switch ($type) {
            case 1: $name = "⚖️ Gewicht"; $suffix = " kg"; $icon = "Scale"; break;
            case 4: $name = "📏 Größe"; $suffix = " m"; $icon = "Distance"; break;
            case 5: $name = "💪 Fettfreie Masse"; $suffix = " kg"; $icon = "Scale"; break;
            case 6: $name = "🥓 Körperfett"; $suffix = " %"; $icon = "Drop"; break;
            case 8: $name = "🧈 Fettmasse"; $suffix = " kg"; $icon = "Scale"; break;
            case 9: $name = "❤️ Blutdruck (Diastolisch)"; $suffix = " mmHg"; $icon = "Heart"; break;
            case 10: $name = "❤️ Blutdruck (Systolisch)"; $suffix = " mmHg"; $icon = "Heart"; break;
            case 11: $name = "💓 Herzfrequenz"; $suffix = " bpm"; $icon = "Heart"; break;
            case 12: 
            case 54: $name = "🩸 SPO2 (Sauerstoffsättigung)"; $suffix = " %"; $icon = "Heart"; break;
            case 71: 
            case 73: $name = "🌡️ Temperatur"; $suffix = " °C"; $icon = "Temperature"; break;
            case 76: $name = "🦾 Muskelmasse"; $suffix = " kg"; $icon = "Scale"; break;
            case 77: $name = "💧 Wasseranteil"; $suffix = " kg"; $icon = "Drop"; break;
            case 88: $name = "🦴 Knochenmasse"; $suffix = " kg"; $icon = "Scale"; break;
            case 91: $name = "🫀 Pulswellengeschwindigkeit"; $suffix = " m/s"; $icon = "Wind"; break;
            case 123: $name = "🫁 VO2 Max"; $suffix = " ml/min/kg"; $icon = "Heart"; break;
            case 130: $name = "🥓 Viszeralfett"; $suffix = " %"; $icon = "Drop"; break;
            case 135: 
            case 155: $name = "Gefäßalter"; $suffix = " Jahre"; $icon = "Clock"; break;
            case 136: $name = "Nervenaktivität"; $suffix = " Punkte"; $icon = "Intensity"; break;
            case 168: $name = "Extrazelluläres Wasser"; $suffix = " kg"; $icon = "Drop"; break;
            case 169: $name = "Intrazelluläres Wasser"; $suffix = " kg"; $icon = "Drop"; break;
            // Body Scan segmented data
            case 170: $name = "Körperfett Rumpf"; $suffix = " %"; $icon = "Drop"; break;
            case 171: $name = "Körperfett Arme"; $suffix = " %"; $icon = "Drop"; break;
            case 172: $name = "Körperfett Beine"; $suffix = " %"; $icon = "Drop"; break;
            case 173: $name = "Fettfreie Masse (Segment)"; $suffix = " kg"; $icon = "Scale"; break;
            case 174: $name = "Fettmasse (Segment)"; $suffix = " kg"; $icon = "Scale"; break;
            case 175: $name = "Muskelmasse (Segment)"; $suffix = " kg"; $icon = "Scale"; break;
            // Newer Body Scan metrics (EDA / Nerve Health)
            case 196: $name = "Nervenaktivität Score"; $suffix = " Punkte"; $icon = "Intensity"; break;
            case 197: $name = "Nervenaktivität (Fuß links)"; $suffix = " Punkte"; $icon = "Intensity"; break;
            case 198: $name = "Nervenaktivität (Fuß rechts)"; $suffix = " Punkte"; $icon = "Intensity"; break;
            case 226: $name = "Grundumsatz (BMR)"; $suffix = " kcal"; $icon = "Flame"; break;
            case 227: $name = "Metabolisches Alter"; $suffix = " Jahre"; $icon = "Clock"; break;
        }

        return [
            'name' => $name,
            'suffix' => $suffix,
            'icon' => $icon
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
                    IPS_SetVariableCustomPresentation($childID, ['SUFFIX' => $config['suffix']]);
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

        $ident = "Measure_" . $type;
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
                    IPS_SetVariableCustomPresentation($varID, ['SUFFIX' => $config['suffix']]);
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
        $apiKey = trim($this->ReadPropertyString("GeminiApiKey"));
        if ($apiKey === "") {
            $this->Log("Gemini API Key fehlt. KI Auswertung abgebrochen.");
            return;
        }

        $archiveIDs = IPS_GetInstanceListByModuleID("{43192F0B-135B-4CE7-A0A7-1475603F3060}");
        if (count($archiveIDs) == 0) {
            $this->Log("Kein Archive Control gefunden.");
            return;
        }
        $archiveID = $archiveIDs[0];

        $days = $this->ReadPropertyInteger("ArchiveDays");
        $startTime = time() - ($days * 24 * 60 * 60);
        
        $metrics = [
            1 => "Gewicht (kg)",
            6 => "Körperfett (%)",
            11 => "Herzfrequenz (bpm)",
            9 => "Blutdruck diastolisch (mmHg)",
            10 => "Blutdruck systolisch (mmHg)",
            76 => "Muskelmasse (kg)",
            77 => "Wasseranteil (kg)"
        ];

        $prompt = "Du bist ein motivierender KI-Gesundheits-Coach. Hier sind meine aufgezeichneten Gesundheitsdaten der letzten " . $days . " Tage.\n";
        $prompt .= "Bitte bewerte den Trend der Messwerte, gib mir ein kurzes Feedback und weise auf Besonderheiten hin (z.B. stark steigender Blutdruck oder Gewichtsverlust).\n";
        $prompt .= "Fasse dich kurz, bleibe positiv und präzise. Antworte in Deutsch und formatiere den Text in einfachem Markdown.\n\n";

        $hasData = false;
        foreach ($metrics as $type => $label) {
            $ident = "Measure_" . $type;
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
            $this->Log("Keine Archivdaten für Gemini Auswertung gefunden.");
            return;
        }

        $model = $this->ReadPropertyString("GeminiModel");
        $url = "https://generativelanguage.googleapis.com/v1beta/models/" . $model . ":generateContent?key=" . $apiKey;
        
        $payload = [
            'contents' => [
                [
                    'role' => 'user',
                    'parts' => [
                        ['text' => $prompt]
                    ]
                ]
            ],
            'generationConfig' => [
                'temperature' => 0.4
            ]
        ];

        $jsonPayload = json_encode($payload);
        
        $script = '<?php
            $ch = curl_init("' . $url . '");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, ' . var_export($jsonPayload, true) . ');
            curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);
            $result = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            WITHINGS_ProcessGeminiResponse(' . $this->InstanceID . ', $result, $httpCode);
        ';
        IPS_RunScriptText($script);
    }

    public function ProcessGeminiResponse(string $result, int $httpCode) {
        if ($httpCode === 200 && $result) {
            $data = json_decode($result, true);
            if (isset($data['candidates'][0]['content']['parts'][0]['text'])) {
                $report = $data['candidates'][0]['content']['parts'][0]['text'];
                $this->SetValue("DailyReport", $report);
                $this->Log("Gemini Bericht erfolgreich generiert.");
                
                $smtpID = $this->ReadPropertyInteger("SMTPInstanceID");
                if ($smtpID > 0 && IPS_InstanceExists($smtpID)) {
                    @SMTP_SendMail($smtpID, "Dein Gesundheits-Coach Update", $report);
                }
            }
        } else {
            $this->Log("Fehler bei Gemini API (HTTP $httpCode): " . substr($result, 0, 200));
        }
    }

    protected function LogMessage(string $Message, int $Type): bool
    {
        IPS_LogMessage('SmartVillaKunterbunt', 'WithingsDevice: ' . $Message);
        return true;
    }
}

?>
