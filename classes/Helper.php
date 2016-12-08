<?php

namespace Grav\Plugin\GitSync;

use SebastianBergmann\Git\RuntimeException;

class Helper {

    /**
     * Checks if the user/ folder is already initialized
     *
     * @return bool
     */
    public static function isGitInitialized() {
        return file_exists(rtrim(USER_DIR, '/') . '/.git');
    }

    public static function prepareRepository($user, $password, $repository)
    {
        return str_replace('://', "://${user}:${password}@", $repository);
    }

    public static function testRepository($user, $password, $repository) {
        $git = new GitSync();
        $repository = self::prepareRepository($user, $password, $repository);

        try {
            return $git->testRepository($repository);
        } catch (RuntimeException $e) {
            return $e->getMessage();
        }
    }
}