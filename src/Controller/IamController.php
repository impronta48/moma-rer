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
            throw new \Exception("Codice fiscale non fornito negli header. Autenticazione IAM fallita.");
        }
        $user = $users->find()->where(['cf' => $cf])->first();
        if ($user) {
            $token = $user->getToken($user->id);  
            // Imposta cookie HttpOnly + Secure

            //  Crea l'oggetto Cookie
            $cookie = new Cookie(
                'jwt_token',
                $token,
                new \DateTime('+5 minutes'),
                '/',
                null, // dominio (null = automatico)
                true, // secure
                true, // httpOnly
                'Lax' // SameSite
            );

            //  Aggiungi il cookie alla response
            $this->response = $this->response->withCookie($cookie);
        }
        else {
            // Utente non trovato, gestire l'errore di conseguenza
            $message = "Utente con codice fiscale $cf non trovato. Autenticazione IAM fallita.";
            $this->log($message, 'error');
        }
        $fullbaseUrl = "https://$_SERVER[HTTP_HOST]";
        $frontendUrl = Configure::read('FRONTEND_URL') ?: $fullbaseUrl;
        // Reindirizza alla home dell'applicazione        
        return $this->redirect("$frontendUrl/login?message=" . urlencode($message ?? "Autenticazione IAM completata con successo."));

        exit();
    }

}