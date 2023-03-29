package com.auth.security.controllers

import com.auth.security.models.Message
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/test")
class TestController {

    @GetMapping
    fun dayHello(): ResponseEntity<Message> {
        return ResponseEntity.ok(Message("Hello"))
    }
}