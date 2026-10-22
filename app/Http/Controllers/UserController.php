<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Token;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Exception;

class UserController extends Controller
{
    public function create(Request $request)
    {
        try {
            $data = $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|string|min:8'
            ]);

            $data['password'] = Hash::make($data['password']);

            User::create($data);

            return redirect()->route('home')->with('success', 'Tu cuenta ha sido creada.');
        } catch(Exception $exception) {
            return back()->with('error', 'Error al crear cuenta: ' . $exception->getMessage());
        }
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required'
        ]);

        $user = User::where('email', $request->email)->first();

        if ($user && Hash::check($request->password, $user->password)) {
            $tokenString = Str::random(60);

            Token::create([
                'user_id' => $user->id,
                'token' => $tokenString
            ]);

            session(['token' => $tokenString, 'name' => $user->name]);

            return redirect()->route('home')->with('success', 'Sesión iniciada correctamente.');
        }

        return back()->with('error', 'Las credenciales no son correctas.');
    }

    public function logout(Request $request)
    {
        $tokenString = session('token');

        if ($tokenString) {
            Token::where('token', $tokenString)->delete();
        }

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('view.login');
    }
}