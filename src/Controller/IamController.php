<?php
namespace Rer\Controller;

use Cake\Core\Configure;
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
        $fullbaseUrl = "https://$_SERVER[HTTP_HOST]";
        $frontendUrl = Configure::read('FRONTEND_URL') ?: $fullbaseUrl;
        $route = $this->request->getUri()->getPath();
        $method = ($route === '/rer/spid') ? 'SPID' : 'CREDENZIALI REGIONALI IAM';

        // Lettura degli header HTTP
        $cf = $_SERVER['HTTP_CODICEFISCALE'] ?? null;
        $nome = $_SERVER['HTTP_NOME'] ?? null;
        $cognome = $_SERVER['HTTP_COGNOME'] ?? null;
        $email = $_SERVER['HTTP_EMAILADDRESS'] ?? null;
        $trust = $_SERVER['HTTP_TRUSTLEVEL'] ?? 'Basso';
        $policy = $_SERVER['HTTP_POLICYLEVEL'] ?? 'Basso';

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
            return $this->redirect("$frontendUrl/login?message=" . urlencode($message ?? "Autenticazione $method completata con successo."));
        }
        /** @var \App\Model\Entity\User|null $user */
        $user = $users->find()->where(['cf' => $cf])->first();
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
        return $this->redirect("$frontendUrl/login?message=" . urlencode($message ?? "Autenticazione $method completata con successo."));
        exit();
    }

}