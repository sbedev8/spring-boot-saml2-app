package com.sbe.saml.samlapp.config;

import org.opensaml.security.x509.X509Support;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

//    @Value("${verification.key}")
//    File verificationKey;
//
//
//    @Value("${public.certificate}")
//    File certificate;
//    @Value("${private.key}")
//    File key;

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        RelyingPartyRegistration registration = this.relyingPartyRegistrationRepository.findByRegistrationId("sbe");
        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(groupsConverter());

        DefaultRelyingPartyRegistrationResolver relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
        Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login/**", "/saml2/**").permitAll()
                        .anyRequest()
                        .authenticated())
//                .saml2Login(Customizer.withDefaults())
                .saml2Login(saml2 -> saml2
                        .authenticationManager(new ProviderManager(authenticationProvider)))
                .saml2Logout(Customizer.withDefaults())
                .addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);
        DefaultSecurityFilterChain chain = http.build();
        return chain;
    }

    private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> groupsConverter() {

        Converter<ResponseToken, Saml2Authentication> delegate =
                OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

        return (responseToken) -> {
            Saml2Authentication authentication = delegate.convert(responseToken);
            Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
            List<String> groups = principal.getAttribute("groups");
            Set<GrantedAuthority> authorities = new HashSet<>();
            if (groups != null) {
                groups.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
            } else {
                authorities.addAll(authentication.getAuthorities());
            }
            System.out.println(authorities);
            return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
        };
    }

//@Bean
//public Saml2X509Credential assertingPartyVerifyingCredential() throws Exception {
//    // Load your certificate from file, classpath, etc.
//    File certificateFile = new File("path-to-your-certificate.pem");
//    FileInputStream inputStream = new FileInputStream(certificateFile);
//    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//    X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
//
//    // Create a Saml2X509Credential for verification.
//    return Saml2X509Credential.verification(certificate);
//}


//    @Bean
//    public RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
//        X509Certificate certificate = X509Support.decodeCertificate(this.verificationKey);
//        Saml2X509Credential credential = Saml2X509Credential.verification(Objects.requireNonNull(certificate));
//
//
//        String privateKeyContent = new String(Files.readAllBytes(key.toPath()))
//                .replaceAll("\\n", "")
//                .replace("-----BEGIN PRIVATE KEY-----", "")
//                .replace("-----END PRIVATE KEY-----", "");
//
//// Génère PrivateKey à partir du contenu
//        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(
//                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent))
//        );
//
//// Lire le certificat
//        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//        X509Certificate certificate2 = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(this.certificate));
//
//// Utilisez privateKey et certificate ici
//        Saml2X509Credential credentialServer = Saml2X509Credential.signing(privateKey, certificate2);
//
//        RelyingPartyRegistration registration = RelyingPartyRegistration
//                .withRegistrationId("sbe")
//                .assertingPartyDetails(party -> party
//                        .entityId("http://www.okta.com/exk6g0qd77EUYXRpW697")
//                        .singleSignOnServiceLocation("https://trial-6974822.okta.com/app/trial-6974822_smal2app_1/exk6g0qd77EUYXRpW697/sso/saml")
//                        .wantAuthnRequestsSigned(false)
//                        .verificationX509Credentials(c -> c.add(credential))
//                )
//                .build();
//
////
//        RelyingPartyRegistration registration2 = RelyingPartyRegistrations
//                .fromMetadataLocation("https://trial-6974822.okta.com/app/exk6g0qd77EUYXRpW697/sso/saml/metadata")
//                .signingX509Credentials((signing) -> signing.add(credentialServer))
//                .singleLogoutServiceLocation("http://localhost:8084/logout/saml2/slo")
//                .build();
//        return new InMemoryRelyingPartyRegistrationRepository(registration);
//    }


//@PostConstruct
//public void init() throws Exception {
////    String certificateString = StreamUtils.copyToString(certificateResource.getInputStream(), Charset.defaultCharset());
//    X509Certificate certificate = X509Support.decodeCertificate(this.verificationKey);
//    Saml2X509Credential credential = Saml2X509Credential.verification(certificate);
//
//    RelyingPartyRegistration registration = RelyingPartyRegistration
//            .withRegistrationId("sbe")
//            .assertingPartyDetails(s -> s
//                    .entityId("http://www.okta.com/exk6g0qd77EUYXRpW697")
//                    .singleSignOnServiceLocation("https://trial-6974822.okta.com/app/trial-6974822_smal2app_1/exk6g0qd77EUYXRpW697/sso/saml")
//                    .wantAuthnRequestsSigned(false)
//                    .verificationX509Credentials(c -> c.add(credential))
//            )
//            .singleLogoutServiceLocation("http://localhost:8084/logout/saml2/slo")
//            .build();
//
//    this.registrations = new InMemoryRelyingPartyRegistrationRepository(registration);
//}
//
//    @Bean
//    public RelyingPartyRegistrationRepository relyingPartyRegistrations() {
//        return this.registrations;
//    }

//    @Bean
//    SecurityFilterChain configure(HttpSecurity http) throws Exception {
//
//        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
//        authenticationProvider.setResponseAuthenticationConverter(groupsConverter());
//
//        http.authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/login/**", "/saml2/**").permitAll()
//                        .anyRequest().authenticated())
//                .saml2Login(saml2 -> saml2
//                        .authenticationManager(new ProviderManager(authenticationProvider)))
//                .saml2Logout(Customizer.withDefaults());
//
//        return http.build();
//    }


}
