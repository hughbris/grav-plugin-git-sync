<?php
namespace Grav\Plugin\GitSync;

use Grav\Common\Grav;
use Grav\Common\Plugin;
use RocketTheme\Toolbox\File\File;
use SebastianBergmann\Git\Git;

class GitSync extends Git
{
    private $user;
    private $password;
    protected $grav;
    protected $config;
    static public $instance = null;

    public function __construct(Plugin $plugin = null)
    {
        parent::__construct(USER_DIR);
        static::$instance = $this;
        $this->grav = Grav::instance();
        $this->config = $this->grav['config']->get('plugins.git-sync');

        $this->user = $this->config['user'];
        $this->password = $this->config['password'];

        unset($this->config['user']);
        unset($this->config['password']);
    }

    static public function instance()
    {
        return static::$instance = is_null(static::$instance) ? new static : static::$instance;
    }

    public function setConfig($obj)
    {
        $this->config = $obj;
    }

    public function testRepository($url)
    {
        return $this->execute("ls-remote '${url}'");
    }

    public function initializeRepository($force = false)
    {
        if ($force || !Helper::isGitInitialized()) {
            $this->execute('init');
            return $this->enableSparseCheckout();
        }

        return true;
    }

    public function setUser($name, $email)
    {
        $this->execute("config user.name '{$name}'");
        $this->execute("config user.email '{$email}'");

        return true;
    }

    public function hasRemote($name)
    {
        try {
            $this->execute("remote get-url '{$name}'");
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    public function enableSparseCheckout()
    {
        $folders = $this->config['folders'];
        $this->execute("config core.sparsecheckout true");

        $sparse = [];
        foreach ($folders as $folder) {
            $sparse[] = $folder;
        }

        $file = File::instance(rtrim(USER_DIR, '/') . '/.git/info/sparse-checkout');
        $file->save(implode("\r\n", $sparse));
        $file->free();

        $ignore = ['/*'];
        foreach ($folders as $folder) {
            $ignore[] = '!/' . $folder;
        }

        $file = File::instance(rtrim(USER_DIR, '/') . '/.gitignore');
        $file->save(implode("\r\n", $ignore));
        $file->free();
    }

    public function addRemote($alias, $url)
    {
        $command = $this->hasRemote($alias) ? 'set-url' : 'add';
        $url = Helper::prepareRepository($this->user, $this->password, $url);

        return $this->execute("remote ${command} ${alias} '${url}'");
    }

    public function add()
    {
        $folders = $this->config['folders'];
        $paths = [];

        foreach ($folders as $folder) {
            $paths[] = $folder;
        }

        return $this->execute('add ' . implode(' ', $paths));
    }

    public function commit($message = '(Grav GitSync) Automatic Commit')
    {
        $this->add();
        return $this->execute("commit -m " . escapeshellarg($message));
    }

    public function fetch($name, $branch)
    {
        return $this->execute("fetch {$name} {$branch}");
    }

    public function pull($name, $branch)
    {
        return $this->execute("pull {$name} {$branch}");
    }

    public function push($name, $branch)
    {
        return $this->execute("push {$name} {$branch}");
    }

    public function sync($name, $branch)
    {
        $this->fetch($name, $branch);
        $this->pull($name, $branch);
        $this->push($name, $branch);

        return true;
    }

    public function execute($command)
    {
        try {
            return parent::execute($command . ' 2>&1');
        } catch (\RuntimeException $e) {
            $message = $e->getMessage();
            $message = str_replace($this->password, '{password}', $message);
            throw new \RuntimeException($message);
        }
    }
}