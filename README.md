<?php
/**
 * BK GERADOR PHP - INSTALADOR AUTOMÁTICO COMPLETO (TUDO-EM-UM)
 * Executa a auto-extração de arquivos estruturais e cria o ambiente seguro.
 */

$arquivos_instalados = true;
$arquivos_necessarios = ['config.php', 'check.php', 'admin.php', '.htaccess'];

foreach ($arquivos_necessarios as $arq) {
    if (!file_exists(__DIR__ . '/' . $arq)) {
        $arquivos_instalados = false;
        break;
    }
}

// SE JÁ ESTIVER INSTALADO, REDIRECIONA DIRETAMENTE PARA O PAINEL ADMIN
if ($arquivos_instalados) {
    header("Location: admin.php");
    exit;
}

// --- CONFIGURAÇÃO AUTOMÁTICA DOS COMPONENTES ---

// 1. GERANDO .HTACCESS
$htaccess_content = <<<'EOD'
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

<FilesMatch "^(config\.php|banco_dados\.db)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>

Options -Indexes

<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
</IfModule>
EOD;

// 2. GERANDO CONFIG.PHP (Usando SQLite nativo para hospedagem instantânea sem complicação)
$config_content = <<<'EOD'
<?php
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);

define('DB_FILE', __DIR__ . '/banco_dados.db');
define('MASTER_API_KEY', 'BK_SECURE_TOKEN_7RNS_2026_#9a8b7c6d5e4f');
define('ADMIN_PASSWORD_HASH', '$2y$10$mC1h4n/NfU9H6Xo3/iW/UuH8R9QeZ6rO7E2vB3Z9G5qT.tN2lI9g.'); // Senha: admin123

$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
$domain = $_SERVER['HTTP_HOST'];
define('BASE_URL', $protocol . $domain);

try {
    $pdo = new PDO("sqlite:" . DB_FILE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    
    // Criação das tabelas caso não existam (SQLite syntax)
    $pdo->exec("CREATE TABLE IF NOT EXISTS chaves_pysico (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chave TEXT NOT NULL UNIQUE,
        hwid TEXT DEFAULT NULL,
        data_expiracao TEXT NOT NULL,
        status TEXT DEFAULT 'ativo',
        criada_em TEXT DEFAULT CURRENT_TIMESTAMP,
        ultimo_uso TEXT DEFAULT NULL,
        versao_mod TEXT DEFAULT NULL
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        chave TEXT DEFAULT NULL,
        hwid TEXT DEFAULT NULL,
        versao_mod TEXT DEFAULT NULL,
        resultado TEXT NOT NULL,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Inserir chave teste padrão se a tabela estiver vazia
    $count = $pdo->query("SELECT COUNT(*) FROM chaves_pysico")->fetchColumn();
    if ($count == 0) {
        $pdo->exec("INSERT INTO chaves_pysico (chave, hwid, data_expiracao, status, versao_mod) 
                    VALUES ('PYS-TESTE1-VALIDO', NULL, '2027-12-31 23:59:59', 'ativo', '1.0')");
    }

} catch (PDOException $e) {
    error_log("Erro Base: " . $e->getMessage());
    header('HTTP/1.1 500 Internal Server Error');
    exit('Erro interno do servidor.');
}
EOD;

// 3. GERANDO CHECK.PHP
$check_content = <<<'EOD'
<?php
require_once 'config.php';

header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Content-Type: text/plain; charset=UTF-8");
header("Access-Control-Allow-Origin: " . BASE_URL);
header("Content-Security-Policy: default-src 'none';");

$ip = $_SERVER['REMOTE_ADDR'];
$rate_limit_dir = __DIR__ . '/cache_rate/';
if (!is_dir($rate_limit_dir)) {
    mkdir($rate_limit_dir, 0700, true);
}

$ip_file = $rate_limit_dir . md5($ip) . '.json';
$now = time();

if (file_exists($ip_file)) {
    $data = json_decode(file_get_contents($ip_file), true);
    if (isset($data['blocked_until']) && $data['blocked_until'] > $now) {
        header('HTTP/1.1 429 Too Many Requests');
        exit('0');
    }
    if ($now - $data['start_time'] > 60) {
        $data = ['start_time' => $now, 'requests' => 1];
    } else {
        $data['requests']++;
    }
} else {
    $data = ['start_time' => $now, 'requests' => 1];
}

if ($data['requests'] > 30) {
    $data['blocked_until'] = $now + 300; 
    file_put_contents($ip_file, json_encode($data));
    header('HTTP/1.1 429 Too Many Requests');
    exit('0');
}
file_put_contents($ip_file, json_encode($data));

$headers = getallheaders();
$api_key = isset($headers['X-API-Key']) ? $headers['X-API-Key'] : (isset($headers['x-api-key']) ? $headers['x-api-key'] : '');

if (empty($api_key) || !hash_equals(MASTER_API_KEY, $api_key)) {
    header('HTTP/1.1 401 Unauthorized');
    exit('0');
}

$key_input   = isset($_GET['key']) ? trim(filter_var($_GET['key'], FILTER_SANITIZE_SPECIAL_CHARS)) : '';
$hwid_input  = isset($_GET['hwid']) ? trim(filter_var($_GET['hwid'], FILTER_SANITIZE_SPECIAL_CHARS)) : '';
$versao_input = isset($_GET['versao']) ? trim(filter_var($_GET['versao'], FILTER_SANITIZE_SPECIAL_CHARS)) : '';

if (empty($key_input) || empty($hwid_input)) {
    exit('0');
}

function registrar_log($pdo, $ip, $key, $hwid, $versao, $resultado) {
    $stmt = $pdo->prepare("INSERT INTO logs (ip, chave, hwid, versao_mod) VALUES (?, ?, ?, ?)");
    $stmt->execute([$ip, $key, $hwid, $versao]);
}

try {
    $stmt = $pdo->prepare("SELECT * FROM chaves_pysico WHERE chave = ? LIMIT 1");
    $stmt->execute([$key_input]);
    $chave_db = $stmt->fetch();

    if (!$chave_db || $chave_db['status'] === 'banido' || strtotime($chave_db['data_expiracao']) < $now) {
        registrar_log($pdo, $ip, $key_input, $hwid_input, $versao_input, '0');
        exit('0');
    }

    if (empty($chave_db['hwid'])) {
        $update = $pdo->prepare("UPDATE chaves_pysico SET hwid = ?, ultimo_uso = datetime('now','localtime'), versao_mod = ? WHERE id = ?");
        $update->execute([$hwid_input, $versao_input, $chave_db['id']]);
    } else {
        if (!hash_equals($chave_db['hwid'], $hwid_input)) {
            registrar_log($pdo, $ip, $key_input, $hwid_input, $versao_input, '0');
            exit('0');
        }
        $update = $pdo->prepare("UPDATE chaves_pysico SET ultimo_uso = datetime('now','localtime'), versao_mod = ? WHERE id = ?");
        $update->execute([$versao_input, $chave_db['id']]);
    }

    registrar_log($pdo, $ip, $key_input, $hwid_input, $versao_input, '1');
    exit('1');
} catch (Exception $e) {
    exit('0');
}
EOD;

// 4. GERANDO ADMIN.PHP
$admin_content = <<<'EOD'
<?php
session_start();
require_once 'config.php';

header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Content-Security-Policy: default-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;");

if (isset($_POST['login'])) {
    $password_input = $_POST['password'] ?? '';
    if (password_verify($password_input, ADMIN_PASSWORD_HASH)) {
        $_SESSION['logged_in'] = true;
        header("Location: admin.php");
        exit;
    } else {
        $error = "Senha incorreta!";
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: admin.php");
    exit;
}

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true):
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8"><title>BK GERADOR - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0b0c10; color: #c5a1ff; font-family: 'Segoe UI', sans-serif; }
        .login-card { background: #1f2833; border: 2px solid #00ffcc; border-radius: 15px; box-shadow: 0 0 20px #00ffcc; }
        .btn-neon { background-color: #7b2cbf; color: #fff; border: 1px solid #00ffcc; }
        .btn-neon:hover { background-color: #00ffcc; color: #000; box-shadow: 0 0 15px #00ffcc; }
    </style>
</head>
<body class="d-flex align-items-center vh-100"><div class="container"><div class="row justify-content-center"><div class="col-md-4">
<div class="card login-card p-4"><h3 class="text-center mb-4 text-white" style="text-shadow: 0 0 10px #7b2cbf;">BK GERADOR</h3>
<?php if(isset($error)): ?><div class="alert alert-danger py-2"><?= $error ?></div><?php endif; ?>
<form method="POST"><div class="mb-3"><label class="form-label">Senha do Painel</label>
<input type="password" name="password" class="form-control bg-dark text-white border-secondary" required></div>
<button type="submit" name="login" class="btn btn-neon w-100 fw-bold">ACESSAR SISTEMA</button></form>
</div></div></div></div></body></html>
<?php exit; endif;

$mensagem = "";
if (isset($_POST['gerar_chave'])) {
    $dias = (int)($_POST['dias'] ?? 30);
    $nova_chave = 'PYS-' . strtoupper(bin2hex(random_bytes(3))) . '-' . strtoupper(bin2hex(random_bytes(3)));
    $data_expiracao = date('Y-m-d H:i:s', strtotime("+$dias days"));
    $stmt = $pdo->prepare("INSERT INTO chaves_pysico (chave, data_expiracao, status) VALUES (?, ?, 'ativo')");
    $stmt->execute([$nova_chave, $data_expiracao]);
    $mensagem = "Chave criada: <strong>$nova_chave</strong>";
}

if (isset($_GET['acao']) && isset($_GET['id'])) {
    $id = (int)$_GET['id'];
    if ($_GET['acao'] === 'banir') $pdo->prepare("UPDATE chaves_pysico SET status = 'banido' WHERE id = ?")->execute([$id]);
    elseif ($_GET['acao'] === 'desbanir') $pdo->prepare("UPDATE chaves_pysico SET status = 'ativo' WHERE id = ?")->execute([$id]);
    elseif ($_GET['acao'] === 'excluir') $pdo->prepare("DELETE FROM chaves_pysico WHERE id = ?")->execute([$id]);
    header("Location: admin.php"); exit;
}

$busca = $_GET['busca'] ?? '';
if (!empty($busca)) {
    $stmt = $pdo->prepare("SELECT * FROM chaves_pysico WHERE chave LIKE ? OR hwid LIKE ? ORDER BY id DESC");
    $stmt->execute(["%$busca%", "%$busca%"]);
    $chaves = $stmt->fetchAll();
} else {
    $chaves = $pdo->query("SELECT * FROM chaves_pysico ORDER BY id DESC LIMIT 50")->fetchAll();
}
$logs = $pdo->query("SELECT * FROM logs ORDER BY id DESC LIMIT 15")->fetchAll();
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8"><title>BK GERADOR - Painel de Controle</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0b0c10; color: #e5d5ff; font-family: 'Segoe UI', sans-serif; }
        .navbar { background-color: #1f2833 !important; border-bottom: 2px solid #7b2cbf; }
        .card-custom { background: #1f2833; border: 1px solid #7b2cbf; border-radius: 8px; }
        .table-custom { color: #e5d5ff; }
        .table-custom th { color: #00ffcc; border-bottom: 2px solid #7b2cbf; }
        .btn-neon-green { background-color: transparent; color: #00ffcc; border: 1px solid #00ffcc; }
        .btn-neon-green:hover { background-color: #00ffcc; color: #000; box-shadow: 0 0 10px #00ffcc; }
        .neon-text { text-shadow: 0 0 8px #00ffcc; color: #00ffcc; }
    </style>
</head>
<body>
<nav class="navbar navbar-dark bg-dark mb-4"><div class="container-fluid">
<span class="navbar-brand mb-0 h1 fw-bold text-white">BK GERADOR <span class="text-info">[7RNS]</span></span>
<div class="d-flex"><span class="navbar-text me-3 text-warning">API Ativa</span><a href="admin.php?logout=1" class="btn btn-outline-danger btn-sm">Sair</a></div>
</div></nav>
<div class="container">
    <?php if(!empty($mensagem)): ?><div class="alert alert-success bg-dark text-white border-success mb-4"><?= $mensagem ?></div><?php endif; ?>
    <div class="row g-4">
        <div class="col-md-4">
            <div class="card card-custom p-3 shadow">
                <h5 class="neon-text mb-3">Gerar Nova Licença</h5>
                <form method="POST"><div class="mb-3"><label class="form-label">Validade (em dias)</label>
                <input type="number" name="dias" value="30" min="1" class="form-control bg-dark text-white border-secondary" required></div>
                <button type="submit" name="gerar_chave" class="btn btn-neon-green w-100 fw-bold">GERAR CHAVE UNIQUE</button></form>
                <hr class="text-secondary my-4">
                <h6 class="text-white mb-2">Instruções da API:</h6>
                <code class="d-block p-2 bg-dark text-warning rounded text-break" style="font-size: 11px;">GET <?= htmlspecialchars(BASE_URL) ?>/check.php?key=CHAVE&hwid=ID&versao=1.0</code>
                <small class="text-secondary d-block mt-2"><strong>Header obrigatório:</strong></small>
                <code class="d-block p-1 bg-dark text-info rounded" style="font-size: 10px;">X-API-Key: <?= MASTER_API_KEY ?></code>
            </div>
        </div>
        <div class="col-md-8">
            <div class="card card-custom p-3 shadow mb-4">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="neon-text m-0">Licenças Cadastradas</h5>
                    <form method="GET" class="d-flex gap-2"><input type="text" name="busca" placeholder="Buscar..." value="<?= htmlspecialchars($busca) ?>" class="form-control form-control-sm bg-dark text-white border-secondary"></form>
                </div>
                <div class="table-responsive">
                    <table class="table table-dark table-hover align-middle table-custom" style="font-size: 13px;">
                        <thead><tr><th>Chave</th><th>HWID Vinculado</th><th>Expiração</th><th>Status</th><th>Ações</th></tr></thead>
                        <tbody>
                            <?php foreach($chaves as $c): ?>
                            <tr>
                                <td class="fw-bold text-white"><?= htmlspecialchars($c['chave']) ?></td>
                                <td class="text-secondary"><?= $c['hwid'] ? htmlspecialchars($c['hwid']) : '<span class="badge bg-warning text-dark">Aguardando</span>' ?></td>
                                <td><?= $c['data_expiracao'] ?></td>
                                <td><span class="badge bg-<?= $c['status'] == 'ativo' ? 'success' : 'danger' ?>"><?= strtoupper($c['status']) ?></span></td>
                                <td>
                                    <?php if($c['status'] == 'ativo'): ?><a href="admin.php?acao=banir&id=<?= $c['id'] ?>" class="btn btn-xs btn-outline-warning py-0 px-1" style="font-size:11px;">Banir</a>
                                    <?php else: ?><a href="admin.php?acao=desbanir&id=<?= $c['id'] ?>" class="btn btn-xs btn-outline-success py-0 px-1" style="font-size:11px;">Reativar</a><?php endif; ?>
                                    <a href="admin.php?acao=excluir&id=<?= $c['id'] ?>" class="btn btn-xs btn-outline-danger py-0 px-1" style="font-size:11px;" onclick="return confirm('Deletar?')">Excluir</a>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="card card-custom p-3 shadow">
                <h5 class="text-white mb-3">Logs de Conexões Recentes</h5>
                <div class="table-responsive">
                    <table class="table table-dark table-striped align-middle" style="font-size: 12px; color: #b1a7c2;">
                        <thead><tr><th>IP</th><th>Chave</th><th>Versão</th><th>Data/Hora</th></tr></thead>
                        <tbody>
                            <?php foreach($logs as $l): ?>
                            <tr><td><?= htmlspecialchars($l['ip']) ?></td><td><?= htmlspecialchars($l['chave']) ?></td><td>v<?= htmlspecialchars($l['versao_mod']) ?></td><td><?= $l['timestamp'] ?></td></tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
EOD;

// --- ESCRITA DE ARQUIVOS EM DISCO ---
file_put_contents(__DIR__ . '/.htaccess', $htaccess_content);
file_put_contents(__DIR__ . '/config.php', $config_content);
file_put_contents(__DIR__ . '/check.php', $check_content);
file_put_contents(__DIR__ . '/admin.php', $admin_content);

// Redireciona imediatamente ao terminar a instalação silenciosa
header("Location: admin.php");
exit;
