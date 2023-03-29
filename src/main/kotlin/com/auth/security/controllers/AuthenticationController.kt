package com.auth.security.controllers

import com.auth.security.models.AuthenticationRequest
import com.auth.security.models.AuthenticationResponse
import com.auth.security.models.RegisterRequest
import com.auth.security.services.AuthenticationService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/auth")
class AuthenticationController(
    private val authenticationService: AuthenticationService
) {

    @PostMapping("/register")
    fun register(@RequestBody body: RegisterRequest): ResponseEntity<AuthenticationResponse> {
        return ResponseEntity.ok(authenticationService.register(body))
    }

    @PostMapping("/authenticate")
    fun authenticate(@RequestBody body: AuthenticationRequest): ResponseEntity<AuthenticationResponse> {
        return ResponseEntity.ok(authenticationService.authenticate(body))
    }
}