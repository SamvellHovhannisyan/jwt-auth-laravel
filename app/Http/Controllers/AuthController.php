<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|min:3|max:20',
            'email' => 'required|email|unique:users,email',
            'password' => [
                'required',
                'string',
                'min:8',
                'confirmed',
                'regex:/[A-Z]/',
                'regex:/[a-z]/',
                'regex:/[0-9]/',
                'regex:/[!@#$%^&*(),.?":{}|<>`]/',
            ],
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json([
            'message' => 'User successfully registered',
            'token' => $token
        ], 201);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        try {
            if (!$token = JWTAuth::attempt($request->only('email', 'password'))) {
                return response()->json(['errors' => ['message' => 'Неправильный email или пароль']], 401);
            }
        } catch (JWTException $e) {
            return response()->json(['errors' => ['message' => 'Could not create token']], 500);
        }

        return response()->json([
            'message' => 'Login successful',
            'token' => $token
        ], 200);
    }

    public function logout(Request $request)
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json(['message' => 'Logged out successfully'], 200);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Could not log out'], 500);
        }
    }
}

