package com.auth.security.services

import com.auth.security.repositories.UserRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class UserDetailsService(private val repository: UserRepository): UserDetailsService {
    override fun loadUserByUsername(username: String): UserDetails {
        return repository.findByEmail(username) ?: throw UsernameNotFoundException("$username not found")
    }

}