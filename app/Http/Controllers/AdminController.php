<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Validator;
use JWTFactory;
use JWTAuth;
use JWTAuthException;
use App\Admin;

class AdminController extends Controller
{


    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        //      config()->set( 'auth.defaults.guard', 'admin' );
        \Config::set('jwt.user', 'App\Admin');
        \Config::set('auth.providers.users.model', \App\Admin::class);
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**
     * Get a JWT token via given credentials.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
        $validator = Validator::make($credentials, [
            'email' => 'required|string|email|max:255',
            'password' => 'required'
        ]);

        $credentials = $request->only('email', 'password');
        $token = null;
        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_credentials'], 401);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'could_not_create_token'], 500);
        }
        // user = JWTAuth::toUser($token);
//                 $user = Auth::user();
        return response()->json(compact('token'));
    }

    public function register(Request $request)
    {

        $validateData = $request->validate([
            'email' => 'required|unique:users|max:255',
            'name' => 'required',
            'password' => 'required|min:6|confirmed'
        ]);

        $data = array();
        $data['name'] = $request->name;
        $data['email'] = $request->email;
        $data['job_title'] = 'boss';
        $data['password'] = Hash::make($request->password);
        DB::table('admins')->insert($data);

        return $this->login($request);
    }

    /**
     * Show the application dashboard.
     *
     * @return \Illuminate\Contracts\Support\Renderable
     */
    public function index()
    {
        return view('admin');
    }

    public function refresh()
    {
        return $this->respondWithToken(JWTAuth::refresh(JWTAuth::parseToken()));
    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }

    /**
     * Get the authenticated User
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        $user = $this->JWTGetUser();


        //return response()->json( JWTAuth::fromUser($user));
        return response()->json($user);
    }

    protected function JWTGetUser()
    {
        try {
            //Access token from the request
            $token = JWTAuth::parseToken();
            //Try authenticating user
            $user = $token->authenticate();
        } catch (TokenExpiredException $e) {
            //Thrown if token has expired
            return $this->unauthorized('Your token has expired. Please, login again.');
        } catch (TokenInvalidException $e) {
            //Thrown if token invalid
            return $this->unauthorized('Your token is invalid. Please, login again.');
        } catch (JWTException $e) {
            //Thrown if token was not found in the request.
            return $this->unauthorized('Please, attach a Bearer Token to your request');
        }
        return $user;
    }

    /**
     * Log the user out (Invalidate the token)
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        // destroy the token
        JWTAuth::invalidate(JWTAuth::getToken());
        //todo in vue remove form cookies user token
        return response()->json(['message' => 'Successfully logged out']);
    }

}
