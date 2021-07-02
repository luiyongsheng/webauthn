<?php

use Illuminate\Support\Facades\Route;

Route::middleware('web')->as('webauthn')->prefix('webauthn')->group(function () {
    Route::post('login/details', [FastLoginController::class, 'loginDetails'])->name('.login.details');
    Route::post('login', [FastLoginController::class, 'login'])->name('.login');

    Route::middleware('auth')->group(function () {
        Route::post('create/details', [FastLoginController::class, 'createDetails'])->name('.create.details');
        Route::post('create', [FastLoginController::class, 'create'])->name('.create');
    });
});
