package com.auth.security.services

import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import java.security.Key
import java.util.*
import kotlin.collections.HashMap
import kotlin.jvm.Throws

@Service
class JwtService {

    companion object {
        const val SECRET_KEY: String = "472B4B6250655368566B5970337336763979244226452948404D635166546A57"
    }

    @Throws(ExpiredJwtException::class)
    fun extractUsername(token: String): String? {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (e: ExpiredJwtException) {
            throw ExpiredJwtException(e.header, e.claims, e.message)
        }
    }

    @Throws(ExpiredJwtException::class)
    fun <T> extractClaim(token: String, claimsResolver: (Claims) -> T) : T? {
        val claims: Claims
        try {
            claims = extractAllClaims(token)
        } catch (e: ExpiredJwtException) {
            throw ExpiredJwtException(e.header, e.claims, e.message)
        }
        return claimsResolver(claims)
    }

    fun generateToken(userDetails: UserDetails): String {
        return generateToken(HashMap(), userDetails)
    }

    fun generateToken(extraClaims: Map<String, Any>, userDetails: UserDetails): String {
        return Jwts.builder()
            .setClaims(extraClaims)
            .setSubject(userDetails.username)
            .setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + 3600000 * 4)) //4 hour
            .signWith(getSignInKey(), SignatureAlgorithm.HS256)
            .compact()
    }

    fun isTokenValid(token: String, userDetails: UserDetails): Boolean {
        val username: String? = extractUsername(token)
        return (username.equals(userDetails.username)) && !isTokenExpired(token)
    }

    fun isTokenExpired(token: String): Boolean {
        return if (extractExpiration(token) == null) {
            true
        } else {
            extractExpiration(token)!!.before(Date())
        }
    }

    fun extractExpiration(token: String): Date? {
        return extractClaim(token, Claims::getExpiration)
    }

    @Throws(ExpiredJwtException::class)
    fun extractAllClaims(token: String): Claims {
        val claims: Claims
        try {
            claims = Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .body
        } catch (e: ExpiredJwtException) {
            println(e.message)
            throw ExpiredJwtException(e.header, e.claims, e.message)
        }
        return claims
    }

    fun getSignInKey(): Key {
        val keyBytes: ByteArray = Decoders.BASE64.decode(SECRET_KEY)
        return Keys.hmacShaKeyFor(keyBytes)
    }
}