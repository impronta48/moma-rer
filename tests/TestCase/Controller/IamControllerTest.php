<?php
declare(strict_types=1);

//<editor-fold desc="Preamble">
/**
 * EMMA(tm) : Electronic Mobility Management Applications
 * Copyright (c) 5T Torino, Regione Piemonte, Città Metropolitana di Torino
 *
 * SPDX-License-Identifier: EUPL-1.2
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright (c) 5T - https://5t.torino.it
 * @link      https://emma.5t.torino.it
 * @license   https://eupl.eu/1.2/it/ EUPL-1.2 license
 */
//</editor-fold>

namespace Rer\Test\TestCase\Controller;

use Cake\Cache\Cache;
use Cake\Core\Configure;
use Cake\Error\Renderer\WebExceptionRenderer;
use Cake\Log\Log;
use Cake\ORM\TableRegistry;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use Rer\Controller\IamController;
use Spid\Test\Fixture\UsersFixture;

/**
 * GET /rer/iam (and /rer/spid): IdP-header login handoff.
 *
 * Requires HTTP_HOST=rer.drupalvm.test (site .env has EXTRA_PLUGINS=Reports,Rer
 * and FRONTEND_URL); skips cleanly when the Rer plugin is not loaded.
 * Reuses the Spid plugin's `users` fixture (stable CF/active combinations),
 * because the `Rer\Test\` namespace has no autoload-dev mapping.
 *
 * @uses \Rer\Controller\IamController
 */
class IamControllerTest extends TestCase
{
    use IntegrationTestTrait;

    private const INACTIVE_TEXT = 'Il tuo utente non è attivo, contatta l\'amministratore per chiedere la riattivazione.';
    private const SUCCESS_TEXT = 'completata con successo';

    /**
     * @var array<string>
     */
    protected $fixtures = [
        'plugin.Spid.Users',
        // The profile chooser (>= 2 active matches) joins Companies; without this fixture the
        // chooser tests only pass when another test run happens to leave the table behind.
        'app.Companies',
        'app.Offices',
    ];

    private $originalRenderer;

    public function setUp(): void
    {
        parent::setUp();
        // The plugin is loaded by Application via the `extraplugins` config (site .env EXTRA_PLUGINS),
        // i.e. only once the first request builds the app, so check the config here.
        if (!in_array('Rer', (array)Configure::read('extraplugins'), true) || !class_exists(IamController::class)) {
            $this->markTestSkipped('Rer plugin not loaded (run with HTTP_HOST=rer.drupalvm.test).');
        }
        $this->originalRenderer = Configure::read('Error.exceptionRenderer');
        Configure::write('Error.exceptionRenderer', WebExceptionRenderer::class);
        // The Spid fixture recreates `users` with a reduced column set: drop any cached
        // (fuller) schema so queries select only the columns that exist.
        Cache::clear('_cake_model_');
        TableRegistry::getTableLocator()->clear();
        Log::drop('iamtest');
        Log::setConfig('iamtest', ['className' => 'Array', 'levels' => ['info']]);
    }

    public function tearDown(): void
    {
        Log::drop('iamtest');
        Configure::write('Error.exceptionRenderer', $this->originalRenderer);
        parent::tearDown();
    }

    private function callIam(string $cf, string $path = '/rer/iam'): void
    {
        $this->configRequest([
            'environment' => [
                'HTTP_HOST' => 'rer.drupalvm.test',
                'HTTP_CODICEFISCALE' => $cf,
                'HTTP_NOME' => 'Test',
                'HTTP_COGNOME' => 'User',
                'HTTP_EMAILADDRESS' => 'test@example.com',
            ],
        ]);
        $this->get($path);
    }

    private function location(): string
    {
        return rawurldecode(str_replace('+', ' ', $this->_response->getHeaderLine('Location')));
    }

    private function logLines(): string
    {
        return implode("\n", Log::engine('iamtest')->read());
    }

    public function testSingleInactiveRedirectsWithInactiveMessageAndNoSession(): void
    {
        $this->callIam(UsersFixture::CF_INACTIVE_MATCH);

        $this->assertResponseCode(302);
        $this->assertStringContainsString('/login?message=', $this->location());
        $this->assertStringContainsString(self::INACTIVE_TEXT, $this->location());
        $this->assertStringNotContainsString(self::SUCCESS_TEXT, $this->location());
        $this->assertCookieNotSet('jwt_token');
        $this->assertCookieNotSet('jwt_refresh_token');

        $user = TableRegistry::getTableLocator()->get('Users')
            ->get('10000000-0000-0000-0000-000000000002');
        $this->assertNull($user->refresh_token);
        $this->assertNull($user->refresh_token_expires);

        $this->assertStringContainsString('Login rejected: user 10000000-0000-0000-0000-000000000002', $this->logLines());
        $this->assertStringContainsString('is not active', $this->logLines());
    }

    public function testInactiveRedirectKeepsReturnUrl(): void
    {
        $this->configRequest(['environment' => ['HTTP_CODICEFISCALE' => UsersFixture::CF_INACTIVE_MATCH]]);
        $this->get('/rer/iam?return_url=' . urlencode('/aziende'));

        $this->assertResponseCode(302);
        $this->assertStringContainsString('&returnUrl=/aziende', $this->location());
        $this->assertCookieNotSet('jwt_token');
    }

    public function testSpidRouteAlsoRefusesInactive(): void
    {
        $this->callIam(UsersFixture::CF_INACTIVE_MATCH, '/rer/spid');

        $this->assertStringContainsString(self::INACTIVE_TEXT, $this->location());
        $this->assertCookieNotSet('jwt_token');
    }

    public function testActiveUserGetsCookiesAndSuccess(): void
    {
        $this->callIam(UsersFixture::CF_ACTIVE_MATCH);

        $this->assertResponseCode(302);
        $this->assertStringContainsString(self::SUCCESS_TEXT, $this->location());
        $this->assertStringNotContainsString(self::INACTIVE_TEXT, $this->location());
        $this->assertCookieIsSet('jwt_token');
        $this->assertCookieIsSet('jwt_refresh_token');

        $user = TableRegistry::getTableLocator()->get('Users')
            ->get('10000000-0000-0000-0000-000000000001');
        $this->assertNotEmpty($user->refresh_token);
    }

    public function testMultipleMatchesOffersOnlyActiveProfiles(): void
    {
        $users = TableRegistry::getTableLocator()->get('Users');
        $users->updateAll(['active' => 0], ['id' => '10000000-0000-0000-0000-000000000004']);

        $this->callIam(UsersFixture::CF_MULTIPLE_MATCH);

        // One active left -> plain login for that profile, the inactive one is not offered.
        $this->assertResponseCode(302);
        $this->assertStringNotContainsString('pendingToken', $this->location());
        $this->assertCookieIsSet('jwt_token');
        $this->assertNotEmpty($users->get('10000000-0000-0000-0000-000000000003')->refresh_token);
        $this->assertNull($users->get('10000000-0000-0000-0000-000000000004')->refresh_token);
    }

    public function testMultipleActiveMatchesShowsChooserWithoutCookies(): void
    {
        $this->callIam(UsersFixture::CF_MULTIPLE_MATCH);

        $this->assertResponseCode(302);
        $this->assertStringContainsString('pendingToken=', $this->location());
        $this->assertStringContainsString('10000000-0000-0000-0000-000000000003', $this->location());
        $this->assertStringContainsString('10000000-0000-0000-0000-000000000004', $this->location());
        $this->assertCookieNotSet('jwt_token');
    }

    public function testMultipleMatchesWithInactiveOneOmitsItFromChooser(): void
    {
        $users = TableRegistry::getTableLocator()->get('Users');
        $extra = $users->newEntity([
            'username' => 'spid.multi3@example.com',
            'email' => 'spid.multi3@example.com',
            'cf' => UsersFixture::CF_MULTIPLE_MATCH,
        ]);
        $extra->id = '10000000-0000-0000-0000-000000000005';
        $extra->password = 'secret';
        $extra->active = false;
        $extra->role = 'user';
        $users->saveOrFail($extra, ['checkRules' => false]);

        $this->callIam(UsersFixture::CF_MULTIPLE_MATCH);

        $this->assertStringContainsString('pendingToken=', $this->location());
        $this->assertStringNotContainsString('10000000-0000-0000-0000-000000000005', $this->location());
        $this->assertCookieNotSet('jwt_token');
    }

    public function testAllMatchesInactiveRedirectsInactive(): void
    {
        $users = TableRegistry::getTableLocator()->get('Users');
        $users->updateAll(['active' => 0], ['cf' => UsersFixture::CF_MULTIPLE_MATCH]);

        $this->callIam(UsersFixture::CF_MULTIPLE_MATCH);

        $this->assertResponseCode(302);
        $this->assertStringContainsString(self::INACTIVE_TEXT, $this->location());
        $this->assertStringNotContainsString('pendingToken', $this->location());
        $this->assertCookieNotSet('jwt_token');
        $this->assertCookieNotSet('jwt_refresh_token');
        $this->assertNull($users->get('10000000-0000-0000-0000-000000000003')->refresh_token);
        $this->assertStringContainsString('Login rejected', $this->logLines());
    }
}
