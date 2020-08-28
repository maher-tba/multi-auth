<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class SecretController extends Controller
{
    public function index(Request $request)
    {
      return $request->user()->secrets;
    }
}
