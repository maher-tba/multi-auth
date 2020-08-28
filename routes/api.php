<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

//Route::get('/secrets', 'SecretController@index');
//Route::post('/register', 'RegisterController@register');
//Route::post('/login', 'LoginController@login');
//Route::post('/logout', 'LoginController@logout');
//
Route::group([

    'middleware' => 'api',
    //'namespace' => 'App\Http\Controllers',
    'prefix' => 'auth'

], function ($router) {

    Route::post('login', 'AuthController@login');
    Route::post('logout', 'AuthController@logout');
    Route::post('register', 'AuthController@register');
    Route::post('refresh', 'AuthController@refresh');
    Route::post('me', 'AuthController@me');

});

Route::group([

    'middleware' => 'api',
    //'namespace' => 'App\Http\Controllers',
    'prefix' => 'admin'

], function ($router) {

    Route::post('login', 'AdminController@login');
    Route::post('register', 'AdminController@register');
    Route::post('logout', 'AdminController@logout');
    Route::post('refresh', 'AdminController@refresh');
    Route::post('me', 'AdminController@me');

});
