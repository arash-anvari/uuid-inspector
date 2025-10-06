<?php
namespace ArashAnvari\UuidInspector;

use Illuminate\Support\Facades\Facade;

class UuidInspectorFacade extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'uuid-inspector';
    }
}
