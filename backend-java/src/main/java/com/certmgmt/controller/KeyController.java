package com.certmgmt.controller;

import com.certmgmt.service.KeyService;
import com.certmgmt.web.ApiException;
import com.certmgmt.web.JwtAuthFilter;
import com.certmgmt.web.dto.Requests.CertificateUploadRequest;
import com.certmgmt.web.dto.Requests.CompromiseRequest;
import com.certmgmt.web.dto.Requests.CreateKeyRequest;
import com.certmgmt.web.dto.Requests.CsrRequest;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/keys")
public class KeyController {

    private final KeyService service;

    public KeyController(KeyService service) {
        this.service = service;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> create(@RequestBody CreateKeyRequest request,
                                      @RequestAttribute(JwtAuthFilter.ACTOR_ATTRIBUTE) String actor) {
        return service.create(request.name(), request.algorithm(), actor);
    }

    @GetMapping
    public Map<String, Object> list(@RequestParam(name = "status", required = false) String status) {
        return service.list(status);
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable String id) {
        return service.get(id);
    }

    @GetMapping("/{id}/private")
    public Map<String, Object> getPrivate(@PathVariable String id,
                                          @RequestAttribute(JwtAuthFilter.ACTOR_ATTRIBUTE) String actor) {
        return service.getPrivateKey(id, actor);
    }

    @PostMapping("/{id}/csr")
    public Map<String, Object> csr(@PathVariable String id,
                                   @RequestBody CsrRequest request,
                                   @RequestAttribute(JwtAuthFilter.ACTOR_ATTRIBUTE) String actor) {
        return service.issueCsr(id, request, actor);
    }

    @PostMapping("/{id}/certificate")
    public Map<String, Object> certificate(@PathVariable String id,
                                           @RequestBody CertificateUploadRequest request,
                                           @RequestAttribute(JwtAuthFilter.ACTOR_ATTRIBUTE) String actor) {
        if (request.certificateChainPem() == null) {
            throw ApiException.invalidRequest("certificateChainPem is required");
        }
        return service.uploadCertificate(id, request.certificateChainPem(), actor);
    }

    @PostMapping("/{id}/activate")
    public Map<String, Object> activate(@PathVariable String id,
                                        @RequestAttribute(JwtAuthFilter.ACTOR_ATTRIBUTE) String actor) {
        return service.activate(id, actor);
    }

    @PostMapping("/{id}/compromise")
    public Map<String, Object> compromise(@PathVariable String id,
                                          @RequestBody(required = false) CompromiseRequest request,
                                          @RequestAttribute(JwtAuthFilter.ACTOR_ATTRIBUTE) String actor) {
        return service.compromise(id, request == null ? null : request.reason(), actor);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable String id,
                       @RequestAttribute(JwtAuthFilter.ACTOR_ATTRIBUTE) String actor) {
        service.delete(id, actor);
    }

    @GetMapping("/{id}/audit")
    public Map<String, Object> audit(@PathVariable String id) {
        return service.auditTrail(id);
    }
}
