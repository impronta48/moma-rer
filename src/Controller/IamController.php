<?php
namespace Rer\Controller;

use Cake\Core\Configure;
use Cake\Log\Log;
use Cake\ORM\TableRegistry;
use App\Controller\AppController as BaseController;
use Cake\Http\Cookie\Cookie;

//** Plugin specifico per l'accesso IAM di Regione Emilia Romagna */

class IamController extends BaseController
{
    public function initialize(): void
    {
        parent::initialize();
        $this->Authentication->allowUnauthenticated(['index', 'spid']);
    }
    //Legge gli header IAM e redirige al frontend con token JWT
    public function index()
    {
        $fullbaseUrl = 'https://' . $this->request->getEnv('HTTP_HOST');
        $frontendUrl = Configure::read('FRONTEND_URL') ?: $fullbaseUrl;
        $route = $this->request->getUri()->getPath();
        $method = ($route === '/rer/spid') ? 'SPID' : 'CREDENZIALI REGIONALI IAM';
        
        // Get return_url from query parameters (passed from frontend login)
        $returnUrl = $this->request->getQuery('return_url');

        // Lettura degli header HTTP
        $cf = $this->request->getEnv('HTTP_CODICEFISCALE');
        $nome = $this->request->getEnv('HTTP_NOME');
        $cognome = $this->request->getEnv('HTTP_COGNOME');
        $email = $this->request->getEnv('HTTP_EMAILADDRESS');
        $trust = $this->request->getEnv('HTTP_TRUSTLEVEL') ?? 'Basso';
        $policy = $this->request->getEnv('HTTP_POLICYLEVEL') ?? 'Basso';

        // Creazione sessione applicativa
        $user =[
            'codice_fiscale' => $cf,
            'nome' => $nome,
            'cognome' => $cognome,
            'email' => $email,
            'trust_level' => $trust,
            'policy_level' => $policy
        ];

        //Genera il token JWT
        /** @var \App\Model\Table\UsersTable $users */
        $users = TableRegistry::getTableLocator()->get('Users');
        // Cerco un utente con quel codice fiscale
        if (!$cf) {
            $this->log("Codice fiscale non fornito negli header. Autenticazione $method fallita.");
            $message = "Codice fiscale non fornito negli header. Autenticazione $method fallita.";
            $redirectUrl = "$frontendUrl/login?message=" . urlencode($message ?? "Autenticazione $method completata con successo.");
            if ($returnUrl) {
                $redirectUrl .= "&returnUrl=" . urlencode($returnUrl);
            }
            return $this->redirect($redirectUrl);
        }
        /** @var \App\Model\Entity\User|null $user */
        $matches = $users->findLoginCandidates('cf', $cf)->all()->toArray();
        // Solo i profili attivi possono accedere: gli inattivi vengono scartati.
        // Se esistono corrispondenze ma nessuna e' attiva, niente cookie ne'
        // refresh token: redirect al login con il messaggio "utente non attivo".
        $found = $matches;
        $matches = array_values(array_filter($matches, fn ($u) => $u->active));
        if ($found && !$matches) {
            $ids = implode(', ', array_map(fn ($u) => "{$u->id} ({$u->email})", $found));
            Log::write('info', "$method: Login rejected: user $ids is not active (CF: $cf)");
            $message = 'Il tuo utente non è attivo, contatta l\'amministratore per chiedere la riattivazione.';
            $redirectUrl = "$frontendUrl/login?message=" . urlencode($message);
            if ($returnUrl) {
                $redirectUrl .= "&returnUrl=" . urlencode($returnUrl);
            }
            return $this->redirect($redirectUrl);
        }

        if (count($matches) > 1) {
            // Login incompleto: nessun cookie, il frontend mostra la scelta del
            // profilo e chiama POST /users/select-profile.json (vedi UsersController).
            $profiles = $users->buildProfileChoices($matches);
            $pendingToken = \App\Model\Entity\User::getPendingLoginToken(array_column($profiles, 'id'));
            $this->log("$method: " . count($profiles) . " profili per CF $cf, scelta richiesta", 'info');

            $redirectUrl = "$frontendUrl/login?pendingToken=" . urlencode($pendingToken)
                . '&profiles=' . urlencode(json_encode($profiles));
            if ($returnUrl) {
                $redirectUrl .= "&returnUrl=" . urlencode($returnUrl);
            }
            return $this->redirect($redirectUrl);
        }

        $user = $matches[0] ?? null;
        if ($user) {
            // Genera access token (3 hours)
            $token = $user->getToken($user->id, HOUR * 3);
            
            // Genera refresh token (30 giorni)
            $refreshToken = $user->getRefreshToken($user->id);
            
            // Salva il refresh token nel database
            $user->refresh_token = $refreshToken;
            $user->refresh_token_expires = date('Y-m-d H:i:s', time() + \App\Model\Entity\User::REFRESH_TOKEN_MONTH_LIVE);
            $users->save($user);
            
            // Imposta cookie HttpOnly + Secure per access token
            $accessCookie = new Cookie(
                'jwt_token',
                $token,
                new \DateTime('+3 hours'), // 3 hours
                '/',
                null, // dominio (null = automatico)
                true, // secure
                true, // httpOnly
                'Lax' // SameSite
            );

            // Imposta cookie HttpOnly + Secure per refresh token (30 giorni)
            $refreshCookie = new Cookie(
                'jwt_refresh_token',
                $refreshToken,
                new \DateTime('+30 days'), // 30 giorni
                '/',
                null, // dominio (null = automatico)
                true, // secure
                true, // httpOnly
                'Lax' // SameSite
            );

            // Aggiungi i cookie alla response
            $this->response = $this->response
                ->withCookie($accessCookie)
                ->withCookie($refreshCookie);
            
            // Log autenticazione IAM con refresh token
            $this->log("$method Authentication successful for user {$user->email} (CF: $cf) - Access and Refresh tokens generated", 'info');
        }
        else {
            // Utente non trovato, gestire l'errore di conseguenza
            $message = "Utente con codice fiscale $cf non trovato. Autenticazione $method fallita. Ti invitiamo a registrarti al sistema prima di effettuare il login tramite $method.";
            $this->log($message, 'error');            
        }

        // Reindirizza alla home dell'applicazione        
        $redirectUrl = "$frontendUrl/login?message=" . urlencode($message ?? "Autenticazione $method completata con successo.");
        if ($returnUrl) {
            $redirectUrl .= "&returnUrl=" . urlencode($returnUrl);
        }
        return $this->redirect($redirectUrl);
    }

}