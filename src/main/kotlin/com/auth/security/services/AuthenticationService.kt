package com.auth.security.services

import com.auth.security.models.*
import com.auth.security.repositories.UserRepository
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.data.crossstore.ChangeSetPersister.NotFoundException
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class AuthenticationService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtService: JwtService,
    private val authenticationManager: AuthenticationManager
) {

    fun register(request: RegisterRequest): AuthenticationResponse {
        val user = User(
            firstname = request.firstname,
            lastname = request.lastname,
            email = request.email,
            password = passwordEncoder.encode(request.password),
            role = Role.USER
        )
        userRepository.save(user)
        val token = jwtService.generateToken(user)
        return AuthenticationResponse(token = token)
    }

    fun authenticate(request: AuthenticationRequest): AuthenticationResponse {
        authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(
                request.email,
                request.password
            )
        )
        val user = userRepository.findByEmail(request.email) ?: throw Exception("Getting user exception")
        val token = jwtService.generateToken(user)
        return AuthenticationResponse(token = token)
    }
}