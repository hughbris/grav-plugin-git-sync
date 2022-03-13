<?php

namespace Grav\Plugin;

use Composer\Autoload\ClassLoader;
use Grav\Common\Config\Config;
use Grav\Common\Data\Data;
use Grav\Common\Grav;
use Grav\Common\Page\Page;
use Grav\Common\Page\Interfaces\PageInterface;
use Grav\Common\Plugin;
use Grav\Common\Scheduler\Scheduler;
use Grav\Plugin\GitSync\AdminController;
use Grav\Plugin\GitSync\GitSync;
use Grav\Plugin\GitSync\Helper;
use RocketTheme\Toolbox\Event\Event;

/**
 * Class GitSyncPlugin
 *
 * @package Grav\Plugin
 */
class GitSyncPlugin extends Plugin
{
    protected $publish_route = 'publish'; // FIXME: this does not route yet

    /** @var AdminController|null */
    protected $controller;
    /** @var GitSync */
    protected $git;

    /**
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return [
            'onPluginsInitialized'   => [
                ['onPluginsInitialized', 1000]
            ],
            'onPageInitialized'      => ['serveHooks', 0],
            # 'onFormProcessed'        => ['onFormProcessed', 0], // doubt I have a use for this
        ];
    }

    /**
     * [onPluginsInitialized:100000] Composer autoload.
     *
     * @return ClassLoader
     */
    public function autoload() : ClassLoader
    {
        return require __DIR__ . '/vendor/autoload.php';
    }

    /**
     * @return string
     */
    public static function generateWebhookSecret()
    {
        return static::generateHash(24);
    }

    /**
     * @return string
     */
    public static function generateRandomWebhook()
    {
        return '/_git-sync-' . static::generateHash(6);
    }

    /**
     * Initialize the plugin
     */
    public function onPluginsInitialized()
    {
        $this->init();

        if ($this->isAdmin()) {
            $this->enable([
                'onAdminPage'   => ['showPublishingForm', 0],
                'onAdminTwigTemplatePaths'  => ['onAdminTwigTemplatePaths', 0],
                'onTwigSiteVariables'  => ['onTwigSiteVariables', 0],
                'onAdminMenu'          => ['showPublishingMenu', 0],
                # 'onAdminSave'          => ['checkStuff', 0], // maybe suppress unnecessary re-numbering by the Admin plugin here
                'onAdminAfterSave'     => ['stageChanges', 0],
                # 'onAdminAfterSaveAs'   => ['onAdminAfterSaveAs', 0], // I don't properly understand this event
                'onAdminAfterDelete'   => ['stageChanges', 0], // it's safest not to try selecting only unstaged deletions, since renames may get caught up in that
                'onAdminAfterAddMedia' => ['stageChanges', 0], // see onAdminAfterDelete above
                'onAdminAfterDelMedia' => ['stageChanges', 0], // see onAdminAfterDelete above
            ]);
        }
    }

    /**
     * Returns true if the request contains a valid signature or token
     * @param  string $secret local secret
     * @return bool           whether or not the request is authorized
     */
    public function isRequestAuthorized($secret)
    {
        if (isset($_SERVER['HTTP_X_HUB_SIGNATURE'])) {
            $payload = file_get_contents('php://input') ?: '';

            return $this->isGithubSignatureValid($secret, $_SERVER['HTTP_X_HUB_SIGNATURE'], $payload);
        }
        if (isset($_SERVER['HTTP_X_GITLAB_TOKEN'])) {
            return $this->isGitlabTokenValid($secret, $_SERVER['HTTP_X_GITLAB_TOKEN']);
        } else {
            $payload = file_get_contents('php://input');
            return $this->isGiteaSecretValid($secret, $payload);
        }

        return false;
    }

    /**
     * Hashes the webhook request body with the client secret and
     * checks if it matches the webhook signature header
     * @param  string $secret The webhook secret
     * @param  string $signatureHeader The signature of the webhook request
     * @param  string $payload The webhook request body
     * @return bool            Whether the signature is valid or not
     */
    public function isGithubSignatureValid($secret, $signatureHeader, $payload)
    {
        [$algorithm, $signature] = explode('=', $signatureHeader);

        return $signature === hash_hmac($algorithm, $payload, $secret);
    }

    /**
     * Returns true if given Gitlab token matches secret
     * @param  string $secret local secret
     * @param  string $token token received from Gitlab webhook request
     * @return bool          whether or not secret and token match
     */
    public function isGitlabTokenValid($secret, $token)
    {
        return $secret === $token;
    }

    /**
     * Returns true if secret contained in the payload matches the client
     * secret
     * @param  string $secret The webhook secret
     * @param  string $payload The webhook request body
     * @return boolean Whether the client secret matches the payload secret or
     * not
     */
    public function isGiteaSecretValid($secret, $payload)
    {
        $payload = json_decode($payload, true);
        if (!empty($payload) && isset($payload['secret'])) {
            return $secret === $payload['secret'];
        }

        return false;
    }

    /**
     * Get admin page template
     */
    public function onAdminTwigTemplatePaths(Event $event) {
        $paths = $event['paths'];
        $paths[] = __DIR__ . DS . 'admin/templates';
        $event['paths'] = $paths;
    }

    public function showPublishingForm($event) { // TODO: stub
        $publish_route = $this->config->get('plugins.admin.route') . '/' . $this->publish_route;

        $uri = $this->grav['uri'];
        if (strpos($publish_route, $uri->path()) === false) {
            return;
        }

        $pages = $this->grav['pages'];
        $page = $pages->dispatch($publish_route);

        if (!$page) {
            // Only add page if it hasn't already been defined.
            $page = new Page;
            $page->init(new \SplFileInfo(__DIR__ . "/admin/pages/publish.md"));
            $page->slug(basename($publish_route));
            $pages->addPage($page, $publish_route);
        }

        $twig = $this->grav['twig'];
        $twig->twig_vars['git_index'] = $this->git->statusSelect($path_filter=TRUE, $env='index', $select='MTDRCA');
    }

    public function showPublishingMenu() {
        $base = rtrim($this->grav['base_url'], '/') . '/' . trim($this->grav['admin']->base, '/');
        $isInitialized = Helper::isGitInitialized();
        $menuLabel = $isInitialized ? 'Publish' : 'Publishing';
        $options = [
            # 'hint' => $isInitialized ? 'Publish' : 'Publication',
            'class' => 'gitsync-sync',
            'location' => 'pages',
            'route' => $isInitialized ? $this->publish_route : 'plugins/git-sync',
            'icon' => 'fa-' . ($isInitialized ? $this->grav['plugins']->get('git-sync')->blueprints()->get('icon') : 'cog'),
        ];

        if (Helper::isGitInstalled()) {
            if ($isInitialized) {
                # $options['data'] = [
                #     'gitsync-useraction' => 'commit',
                #     'gitsync-uri' => $base . '/plugins/git-sync',
                # ];
            }

            $this->grav['twig']->plugins_hooked_nav[$menuLabel] = $options; // TODO: make this configurable in YAML/blueprint
        }
    }

    public function init()
    {
        $this->git = new GitSync();
    }

    /**
     * @return bool
     */
    public function synchronize()
    {
        $this->grav['debugger']->addMessage('GitSyncPlugin->synchronize() was called but has not happened!');
        if (!Helper::isGitInstalled() || !Helper::isGitInitialized()) {
            return true;
        }

        /*
        $this->grav->fireEvent('onGitSyncBeforeSynchronize');

        if ($this->git->hasChangesToCommit()) {
            $this->git->commit();
        }

        // synchronize with remote
        $this->git->sync();

        $this->grav->fireEvent('onGitSyncAfterSynchronize');
        */

        return true;
    }

    // Not sure I will need this...
    /**
     * Add current directory to twig lookup paths.
     */
    public function onTwigTemplatePaths()
    {
        $this->grav['twig']->twig_paths[] = __DIR__ . '/admin/templates';
    }

    /**
     * Set needed variables to display cart.
     *
     * @return bool
     */
    public function onTwigSiteVariables()
    {
        // workaround for admin plugin issue that doesn't properly unsubscribe events upon plugin uninstall
        if (!class_exists(Helper::class)) {
            return false;
        }

        $user = $this->grav['user'];
        if (!$user->authenticated) {
            return false;
        }

        $settings = [
            'first_time'    => !Helper::isGitInitialized(),
            'git_installed' => Helper::isGitInstalled()
        ];

        $this->grav['twig']->twig_vars['git_sync'] = $settings;

        // TODO: can probably eliminate a lot or all JS assets below
        $adminPath = trim($this->grav['admin']->base, '/');
        if ($this->grav['uri']->path() === "/$adminPath/plugins/git-sync") {
            # $this->grav['assets']->addCss('plugin://git-sync/css-compiled/git-sync.css'); // all of that is wizard modal styling
        } else {
            $this->grav['assets']->addInlineJs('var GitSync = ' . json_encode($settings) . ';');
        }

        $this->grav['assets']->addJs('plugin://git-sync/js/vendor.js', ['loading' => 'defer', 'priority' => 0]);
        $this->grav['assets']->addJs('plugin://git-sync/js/app.js', ['loading' => 'defer', 'priority' => 0]);
        $this->grav['assets']->addCss('plugin://git-sync/css-compiled/git-sync-icon.css');

        return true;
    }

    public function serveHooks() {

        $webhooks = $this->config->get("plugins.{$this->name}.webhooks");
        if (!($webhooks['enabled'] ?? FALSE)) {
            return;
        }
        $page = $this->grav['page'] ?? NULL; // CHECKME: may not need this
        // dump($this->grav['uri']->uri(), is_null($page->route())); return;

        if (/* is_null($page->route()) && */ $this->grav['uri']->uri() == $webhooks['path']) { // TODO: just check for uri starting with path here
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                header('Content-Type: application/json');
                if ($webhooks['secret'] ?? false) {
                    if (!$this->isRequestAuthorized($webhooks['secret'])) {
                        http_response_code(401);
                        // TODO: 'WWW-Authenticate' header here??
                        echo json_encode([
                            'status' => 'error',
                            'message' => 'Unauthorized request',
                        ]);
                        exit;
                    }
                }

                // TODO: branch/tag and other condition filtering here - respond with 202 and a "void" status or something (possibly even https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/204 ??)

                // TODO: possibly branch into other hooks here, not just /pull
                try {
                    # $this->synchronize();
                    http_response_code(202);
                    echo json_encode([
                        'status' => 'success',
                        'message' => 'GitSync completed the synchronization',
                    ]);
                } catch (\Exception $e) {
                    http_response_code(500);
                    echo json_encode([
                        'status' => 'error',
                        'message' => 'GitSync failed to synchronize',
                    ]);
                }
            }
            else {
                http_response_code(405);
            }
            exit;
        }

    }

    /**
     * Stage changes and untracked files to the working tree in the selected paths
     *
     * @return void
     */
    public function stageChanges() {
        $filesToStage = GitSync::listFiles($this->git->statusUnstaged());
        $this->grav->fireEvent('onGitSyncBeforeStage');
        $this->git->stageFiles($filesToStage);
        $this->grav->fireEvent('onGitSyncAfterStage');
    }

    /**
     * @param Event $event
     */
    public function onFormProcessed(Event $event)
    {
        $action = $event['action'];

        if ($action === 'gitsync') {
            $this->synchronize();
        }
    }

    /**
     * @param int $len
     * @return string
     */
    protected static function generateHash(int $len): string
    {
        $bytes = openssl_random_pseudo_bytes($len, $isStrong);

        if ($bytes === false) {
            throw new \RuntimeException('Could not generate hash');
        }

        if ($isStrong === false) {
            // It's ok not to be strong [EA].
            $isStrong = true;
        }

        return bin2hex($bytes);
    }
}
