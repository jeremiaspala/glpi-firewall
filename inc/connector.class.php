<?php
/**
 * SSH y Telnet connector
 * sshCommand: SSH no interactivo — ejecuta un comando y termina, igual de rápido que hacerlo a mano
 * sshInteractive: solo para equipos que necesitan enable/secuencia de prompts
 */
class PluginFirewallConnector {

    private int    $sshTimeout;
    private array  $steps_log = [];
    private string $liveLogFile = '';

    public function __construct(string $liveLogFile = '') {
        $this->sshTimeout   = (int) PluginFirewallConfig::get('ssh_timeout', 30);
        $this->liveLogFile  = $liveLogFile;
    }

    public function getStepsLog(): string {
        return implode("\n", $this->steps_log);
    }

    private function log(string $msg): void {
        $line = '[' . date('H:i:s') . '] ' . $msg;
        $this->steps_log[] = $line;
        if ($this->liveLogFile) {
            file_put_contents($this->liveLogFile, $line . "\n", FILE_APPEND | LOCK_EX);
        }
    }

    // -------------------------------------------------------------------------
    // SSH NO INTERACTIVO — el método correcto para la mayoría de equipos
    // Equivale a: sshpass -p '...' ssh user@host 'comando'
    // -------------------------------------------------------------------------
    public function sshCommand(
        string $host,
        int    $port,
        string $user,
        string $pass,
        string $command
    ): string {
        $this->log("SSH → [usuario]@$host:$port");
        $this->log("CMD: $command");

        $passFile = tempnam(sys_get_temp_dir(), 'fwp_');
        file_put_contents($passFile, $pass);
        chmod($passFile, 0600);

        $sshCmd = sprintf(
            'sshpass -f %s ssh'
            . ' -o StrictHostKeyChecking=no'
            . ' -o ConnectTimeout=15'
            . ' -o UserKnownHostsFile=/dev/null'
            . ' -o LogLevel=ERROR'
            . ' -o ServerAliveInterval=10'
            . ' -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group1-sha1'
            . ' -o HostKeyAlgorithms=+ssh-rsa,rsa-sha2-256,rsa-sha2-512'
            . ' -o Ciphers=+aes256-cbc,aes128-cbc,3des-cbc,aes256-ctr,aes128-ctr'
            . ' -o PubkeyAuthentication=no'
            . ' -p %d %s@%s %s',
            escapeshellarg($passFile),
            $port,
            escapeshellarg($user),
            escapeshellarg($host),
            escapeshellarg($command)
        );

        $descriptors = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
        $proc = proc_open($sshCmd, $descriptors, $pipes);

        if (!is_resource($proc)) {
            unlink($passFile);
            throw new \RuntimeException("proc_open falló");
        }

        fclose($pipes[0]);

        // Leer output completo (SSH termina solo cuando el comando termina)
        stream_set_timeout($pipes[1], $this->sshTimeout);
        $output = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($proc);
        unlink($passFile);

        if ($stderr) $this->log("STDERR: " . trim($stderr));
        $this->log("Finalizado. Exit: $exit — " . strlen($output) . " bytes recibidos");

        if ($exit !== 0 && strlen(trim($output)) < 5) {
            $err = trim($stderr) ?: "exit code $exit";
            throw new \RuntimeException("SSH error: $err");
        }

        return $output;
    }

    // -------------------------------------------------------------------------
    // SSH INTERACTIVO — solo para equipos que necesitan secuencia de prompts
    // Steps: ['expect'=>'str','send'=>'cmd','timeout'=>n] | ['drain'=>n] | ['sleep'=>n] | ['send'=>'cmd']
    // -------------------------------------------------------------------------
    public function sshInteractive(
        string $host,
        int    $port,
        string $user,
        string $pass,
        array  $steps
    ): string {
        $this->log("SSH interactivo → [usuario]@$host:$port");

        $passFile = tempnam(sys_get_temp_dir(), 'fwp_');
        file_put_contents($passFile, $pass);
        chmod($passFile, 0600);

        // Opciones de compatibilidad para equipos con firmware/SSH viejo (Cisco ASA, FTD, etc.)
        $sshCmd = sprintf(
            'sshpass -f %s ssh'
            . ' -o StrictHostKeyChecking=no -o ConnectTimeout=15'
            . ' -o BatchMode=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR'
            . ' -o ServerAliveInterval=10'
            . ' -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group1-sha1'
            . ' -o HostKeyAlgorithms=+ssh-rsa,rsa-sha2-256,rsa-sha2-512'
            . ' -o Ciphers=+aes256-cbc,aes128-cbc,3des-cbc,aes256-ctr,aes128-ctr'
            . ' -o MACs=+hmac-sha1,hmac-sha2-256'
            . ' -o PubkeyAuthentication=no'
            . ' -tt -p %d %s@%s',
            escapeshellarg($passFile), $port,
            escapeshellarg($user), escapeshellarg($host)
        );

        $descriptors = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
        $proc = proc_open($sshCmd, $descriptors, $pipes);
        if (!is_resource($proc)) { unlink($passFile); throw new \RuntimeException("proc_open falló"); }

        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $fullOutput = '';
        $n = 0;

        foreach ($steps as $step) {
            $n++;

            // expect + send
            if (isset($step['expect'])) {
                $needle  = $step['expect'];
                $timeout = $step['timeout'] ?? $this->sshTimeout;
                $deadline = time() + $timeout;
                $buf = '';
                $this->log("Paso $n: esperando '$needle' (max {$timeout}s)");

                while (time() < $deadline) {
                    $chunk = fread($pipes[1], 4096);
                    if ($chunk !== false && $chunk !== '') {
                        $buf        .= $chunk;
                        $fullOutput .= $chunk;
                    }
                    $err = fread($pipes[2], 512);
                    if ($err) $this->log("  stderr: " . trim($err));

                    if (strpos($buf, $needle) !== false) {
                        $clean = $this->strip($buf);
                        $this->log("  → encontrado. Output: ..." . substr(trim($clean), -60));
                        break;
                    }
                    usleep(100000);
                }

                if (strpos($buf, $needle) === false) {
                    $clean = $this->strip($buf);
                    $this->log("  TIMEOUT — último output: [" . substr(trim($clean), -150) . "]");
                }
            }

            if (isset($step['send'])) {
                $cmd    = $step['send'];
                $logCmd = ($step['sensitive'] ?? false) ? '***' : $cmd;
                $this->log("Paso $n: send → $logCmd");
                fwrite($pipes[0], $cmd . "\n");
                usleep(200000);
            }

            // drain: lee hasta silencio de 3s o el timeout indicado.
            // 'more' => 'PATTERN': cuando aparece el patrón de paginación, envía espacio y sigue.
            if (isset($step['drain'])) {
                $maxDrain    = (int)$step['drain'];
                $morePattern = $step['more'] ?? null;
                $this->log("Paso $n: drenando output (max {$maxDrain}s, corta a 3s de silencio" . ($morePattern ? ", maneja '$morePattern'" : '') . ")");
                $deadline = time() + $maxDrain;
                $lastData = time();
                while (time() < $deadline) {
                    $chunk = fread($pipes[1], 8192);
                    if ($chunk !== false && $chunk !== '') {
                        $fullOutput .= $chunk;
                        $lastData    = time();
                        // Paginación: enviar espacio para continuar y quitar el prompt del output
                        if ($morePattern && strpos($fullOutput, $morePattern) !== false) {
                            $fullOutput = str_replace($morePattern, '', $fullOutput);
                            fwrite($pipes[0], ' ');
                        }
                    } elseif (time() - $lastData >= 3) {
                        $this->log("  → silencio de 3s, drain terminado. Total: " . strlen($fullOutput) . " bytes");
                        break;
                    } else {
                        usleep(100000);
                    }
                }
            }

            if (isset($step['sleep'])) {
                $this->log("Paso $n: sleep {$step['sleep']}s");
                usleep((int)($step['sleep'] * 1000000));
            }
        }

        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($proc);
        unlink($passFile);

        $this->log("SSH interactivo finalizado. Exit: $exit — " . strlen($fullOutput) . " bytes");
        return $fullOutput;
    }

    // -------------------------------------------------------------------------
    // TELNET
    // -------------------------------------------------------------------------
    public function telnet(
        string $host,
        int    $port,
        string $user,
        string $pass,
        array  $steps
    ): string {
        $timeout = (int) PluginFirewallConfig::get('telnet_timeout', 20);
        $this->log("Telnet → [usuario]@$host:$port");

        $sock = @fsockopen($host, $port, $errno, $errstr, $timeout);
        if (!$sock) throw new \RuntimeException("Telnet $host:$port falló: $errstr ($errno)");
        stream_set_timeout($sock, $timeout);

        $fullOutput = '';
        $n = 0;

        // Negociación IAC inicial
        $deadline = time() + 4;
        while (time() < $deadline) {
            $d = fread($sock, 512);
            if ($d) $fullOutput .= $this->iac($sock, $d);
            else usleep(100000);
        }

        foreach ($steps as $step) {
            $n++;

            if (isset($step['expect'])) {
                $needle  = $step['expect'];
                $timeout = $step['timeout'] ?? $timeout;
                $deadline = time() + $timeout;
                $buf = '';
                $this->log("Paso $n: esperando '$needle'");
                while (time() < $deadline) {
                    $d = fread($sock, 1024);
                    if ($d !== false && $d !== '') {
                        $clean       = $this->iac($sock, $d);
                        $buf        .= $clean;
                        $fullOutput .= $clean;
                    }
                    if (strpos($buf, $needle) !== false) {
                        $this->log("  → encontrado"); break;
                    }
                    usleep(100000);
                }
                if (strpos($buf, $needle) === false)
                    $this->log("  TIMEOUT — último: [" . substr(trim($buf), -100) . "]");
            }

            if (isset($step['send'])) {
                $logCmd = ($step['sensitive'] ?? false) ? '***' : $step['send'];
                $this->log("Paso $n: send → $logCmd");
                fwrite($sock, $step['send'] . "\r\n");
                usleep(200000);
            }

            if (isset($step['drain'])) {
                $deadline = time() + (int)$step['drain'];
                $lastData = time();
                while (time() < $deadline) {
                    $d = fread($sock, 8192);
                    if ($d !== false && $d !== '') { $fullOutput .= $this->iac($sock,$d); $lastData = time(); }
                    elseif (time() - $lastData >= 3) break;
                    else usleep(100000);
                }
            }

            if (isset($step['sleep'])) usleep((int)($step['sleep']*1000000));
        }

        fclose($sock);
        $this->log("Telnet finalizado — " . strlen($fullOutput) . " bytes");
        return $fullOutput;
    }

    private function iac($sock, string $d): string {
        $out = ''; $i = 0; $len = strlen($d);
        while ($i < $len) {
            $c = ord($d[$i]);
            if ($c === 255 && $i+2 < $len) {
                $cmd = ord($d[$i+1]); $opt = ord($d[$i+2]); $i += 3;
                if ($cmd===251||$cmd===252) fwrite($sock, chr(255).chr(254).chr($opt));
                elseif ($cmd===253||$cmd===254) fwrite($sock, chr(255).chr(252).chr($opt));
            } else { $out .= $d[$i++]; }
        }
        return preg_replace('/\x1b\[[0-9;]*[a-zA-Z]|\x1b[()][AB012]|\r/', '', $out);
    }

    private function strip(string $s): string {
        return preg_replace('/\x1b\[[0-9;]*[a-zA-Z]|\x1b[()][AB012]|\r/', '', $s);
    }
}
