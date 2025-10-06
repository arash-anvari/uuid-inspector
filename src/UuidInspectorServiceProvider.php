<?php

namespace ArashAnvari\UuidInspector;

use Illuminate\Support\ServiceProvider;

class UuidInspectorServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton('uuid-inspector', function ($app) {
            return new UuidInspector();
        });

        $this->mergeConfigFrom(
            __DIR__ . '/../config/uuid-inspector.php',
            'uuid-inspector'
        );
    }

    public function boot()
    {
         $this->publishes([
             __DIR__.'/../config/uuid-inspector.php' => config_path('uuid-inspector.php'),
         ], 'config');
    }
}
