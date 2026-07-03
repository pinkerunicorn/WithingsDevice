<?php
declare(strict_types=1);

class SmartWithings extends IPSModule {

    public function Create() {
        parent::Create();
        
        $this->RegisterPropertyString("ClientID", "");
        $this->RegisterPropertyString("ClientSecret", "");
        $this->RegisterPropertyInteger("FetchInterval", 15);
        $this->RegisterPropertyInteger("LastUpdate", 0);

        // Versteckte Attribute für OAuth Tokens
        $this->RegisterAttributeString("AccessToken", "");
        $this->RegisterAttributeString("RefreshToken", "");
        $this->RegisterAttributeInteger("TokenExpires", 0);

        $this->RegisterTimer("FetchTimer", 0, 'SWA_FetchMeasurements($_IPS[\'TARGET\']);');
    }

    public function ApplyChanges() {
        parent::ApplyChanges();
        
        $this->RegisterHook("/hook/smartwithings");

        $interval = $this->ReadPropertyInteger("FetchInterval");
        $this->SetTimerInterval("FetchTimer", $interval * 60 * 1000);
    }

    private function RegisterHook($WebHook) {
        $ids = IPS_GetInstanceListByModuleID("{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}");
        if (count($ids) > 0) {
            $hooks = json_decode(IPS_GetProperty($ids[0], "Hooks"), true);
            if (!is_array($hooks)) {
                $hooks = [];
            }
            $found = false;
            foreach ($hooks as $index => $hook) {
                if ($hook['Hook'] == $WebHook) {
                    if ($hook['TargetID'] == $this->InstanceID) {
                        return;
                    }
                    $hooks[$index]['TargetID'] = $this->InstanceID;
                    $found = true;
                }
            }
            if (!$found) {
                $hooks[] = ['Hook' => $WebHook, 'TargetID' => $this->InstanceID];
            }
            IPS_SetProperty($ids[0], "Hooks", json_encode($hooks));
            IPS_ApplyChanges($ids[0]);
        }
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
        return "http://" . $_SERVER['HTTP_HOST'] . "/hook/smartwithings";
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

    protected function ProcessHookData() {
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
            echo "Erfolgreich autorisiert! Du kannst dieses Fenster nun schließen und in Symcon auf 'Daten jetzt manuell abrufen' klicken.";
        } else {
            echo "Kein Code empfangen.";
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

    public function FetchMeasurements() {
        $accessToken = $this->ReadAttributeString("AccessToken");
        if ($accessToken == "") {
            $this->SendDebug("Fetch", "Kein Access Token vorhanden.", 0);
            return;
        }

        if (time() > $this->ReadAttributeInteger("TokenExpires")) {
            $this->SendDebug("Fetch", "Token abgelaufen, versuche Refresh...", 0);
            if (!$this->RefreshToken()) {
                return;
            }
            $accessToken = $this->ReadAttributeString("AccessToken");
        }

        $lastUpdate = $this->ReadPropertyInteger("LastUpdate");
        $highestUpdate = $lastUpdate;
        $offset = 0;
        $pages = 0;

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
                        }
                        if (isset($grp['measures']) && is_array($grp['measures'])) {
                            foreach ($grp['measures'] as $measure) {
                                $this->ProcessMeasurement($measure, $grpDate);
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
                $this->SendDebug("Fetch", "Fehler beim Abruf: " . $response, 0);
                $offset = 0; // stop on error
            }
        } while ($offset > 0);
        
        if ($highestUpdate > $lastUpdate) {
            IPS_SetProperty($this->InstanceID, "LastUpdate", $highestUpdate);
            IPS_ApplyChanges($this->InstanceID); 
        }
        $this->SendDebug("Fetch", "Abruf erfolgreich beendet (" . $pages . " Seiten).", 0);
    }

    private function ProcessMeasurement($measure, $timestamp) {
        if (!isset($measure['type']) || !isset($measure['value'])) {
            return;
        }
        $type = $measure['type'];
        $unit = isset($measure['unit']) ? $measure['unit'] : 0;
        $value = $measure['value'] * pow(10, $unit);

        $ident = "Measure_" . $type;
        $name = "Messwert Typ " . $type;
        $profile = "";

        switch ($type) {
            case 1: $name = "Gewicht"; break;
            case 4: $name = "Größe"; break;
            case 5: $name = "Fettfreie Masse"; break;
            case 6: $name = "Körperfett"; break;
            case 8: $name = "Fettmasse"; break;
            case 9: $name = "Blutdruck (Diastolisch)"; break;
            case 10: $name = "Blutdruck (Systolisch)"; break;
            case 11: $name = "Herzfrequenz"; break;
            case 12: 
            case 71: 
            case 73: $name = "Temperatur"; break;
            case 76: $name = "Muskelmasse"; break;
            case 77: $name = "Wasseranteil"; break;
            case 88: $name = "Knochenmasse"; break;
            case 91: $name = "Pulswellengeschwindigkeit"; break;
            case 123: $name = "VO2 Max"; break;
            case 130: $name = "Viszeralfett"; break;
            case 135: $name = "Gefäßalter"; break;
            case 136: $name = "Nervenaktivität"; break;
            // Body Scan segmented data
            case 170: $name = "Körperfett Rumpf"; break;
            case 171: $name = "Körperfett Arme"; break;
            case 172: $name = "Körperfett Beine"; break;
            // Newer Body Scan metrics (EDA / Nerve Health)
            case 196: $name = "Nervenaktivität Score"; break;
            case 197: $name = "Nervenaktivität (Fuß links)"; break;
            case 198: $name = "Nervenaktivität (Fuß rechts)"; break;
        }

        // Variable dynamisch anlegen falls nicht existent
        $identCache =& $this->createdIdents;
        if (!isset($identCache)) {
            $identCache = [];
        }

        if (!isset($identCache[$ident]) && !@IPS_GetObjectIDByIdent($ident, $this->InstanceID)) {
            $this->MaintainVariable($ident, $name, 2 /* Float */, $profile, 0, true);
            
            // Logging aktivieren
            $varId = @IPS_GetObjectIDByIdent($ident, $this->InstanceID);
            if ($varId !== false) {
                $archiveIds = IPS_GetInstanceListByModuleID("{43192F0B-135B-4CE7-A0A7-1475603F3060}");
                if (count($archiveIds) > 0) {
                    @AC_SetLoggingStatus($archiveIds[0], $varId, true);
                    @IPS_ApplyChanges($archiveIds[0]);
                }
            }
            $identCache[$ident] = true;
        }

        if (@IPS_GetObjectIDByIdent($ident, $this->InstanceID) !== false) {
            $this->SetValue($ident, $value);
        }
    }
}
?>
