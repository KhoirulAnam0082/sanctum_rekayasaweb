<?php 

namespace App\Http\Controllers\Api; 

use App\Http\Controllers\Controller; 
use App\Models\User; 
use Illuminate\Http\Request; 
use Illuminate\Support\Facades\Auth; 
use Illuminate\Support\Facades\Hash; 
use Illuminate\Support\Facades\Validator; 

class AuthController extends Controller 
{ 
    /**
     * Register a new user.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request) 
    { 
        // Validate input
        $validator = Validator::make($request->all(), [ 
            'name' => 'required|string|max:255', 
            'email' => 'required|string|email|max:255|unique:users', 
            'password' => 'required|string|min:8' 
        ]); 

        if ($validator->fails()) { 
            return response()->json($validator->errors(), 422); 
        } 

        // Create new user
        $user = User::create([ 
            'name' => $request->name, 
            'email' => $request->email, 
            'password' => Hash::make($request->password) 
        ]); 

        // Generate token
        $token = $user->createToken('auth_token')->plainTextToken; 

        return response()->json([ 
            'data' => $user, 
            'access_token' => $token, 
            'token_type' => 'Bearer' 
        ], 201);
    } 

    /**
     * Login a user.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request) 
    { 
        // Attempt login
        if (!Auth::attempt($request->only('email', 'password'))) { 
            return response()->json([ 
                'message' => 'Unauthorized' 
            ], 401); 
        } 

        // Get the authenticated user
        $user = User::where('email', $request->email)->firstOrFail(); 

        // Generate token
        $token = $user->createToken('auth_token')->plainTextToken; 

        return response()->json([ 
            'message' => 'Login success', 
            'access_token' => $token, 
            'token_type' => 'Bearer' 
        ], 200); 
    } 

    /**
     * Logout the user.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout() 
{ 
    // Pastikan user terautentikasi
    $user = Auth::user();
    
    // Jika user terautentikasi, revoke semua token
    if ($user) {
        $user->tokens->each(function ($token) {
            $token->delete();
        });

        return response()->json([ 
            'message' => 'Logout success' 
        ], 200);
    } else {
        return response()->json([
            'message' => 'No user authenticated'
        ], 400);
    }
}
 
}
