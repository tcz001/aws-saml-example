package com.rackspace.saml;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;


public class SamlAssertionProducer {

    private String privateKeyLocation;
    private String publicKeyLocation;
    private CertManager certManager = new CertManager();

    public Response createSAMLResponse(final String subjectId, final DateTime authenticationTime,
                                       final HashMap<String, List<String>> attributes,
                                       String issuer,
                                       Integer samlAssertionDays,
                                       String audience) {

        try {
            DefaultBootstrap.bootstrap();

            Signature signature = createSignature();
            Status status = createStatus();
            Conditions conditions = null;
            Issuer responseIssuer = null;
            Issuer assertionIssuer = null;
            Subject subject = null;
            AttributeStatement attributeStatement = null;

            if (audience != null) {
                conditions = createConditions(audience);
            }

            if (issuer != null) {
                responseIssuer = createIssuer(issuer);
                assertionIssuer = createIssuer(issuer);
            }

            if (subjectId != null && audience != null) {
                subject = createSubject(subjectId, samlAssertionDays, audience);
            }

            if (attributes != null && attributes.size() != 0) {
                attributeStatement = createAttributeStatement(attributes);
            }

            AuthnStatement authnStatement = createAuthnStatement(authenticationTime);

            Assertion assertion = createAssertion(new DateTime(), subject, assertionIssuer, authnStatement, attributeStatement, conditions);

            Response response = createResponse(new DateTime(), responseIssuer, status, assertion);
            response.setSignature(signature);

            ResponseMarshaller marshaller = new ResponseMarshaller();
            Element element = marshaller.marshall(response);

            if (signature != null) {
                Signer.signObject(signature);
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            XMLHelper.writeNode(element, baos);

            return response;

        } catch (Throwable t) {
            t.printStackTrace();
            return null;
        }
    }

    public String getPrivateKeyLocation() {
        return privateKeyLocation;
    }

    public void setPrivateKeyLocation(String privateKeyLocation) {
        this.privateKeyLocation = privateKeyLocation;
    }

    public String getPublicKeyLocation() {
        return publicKeyLocation;
    }

    public void setPublicKeyLocation(String publicKeyLocation) {
        this.publicKeyLocation = publicKeyLocation;
    }

    private Response createResponse(final DateTime issueDate, Issuer issuer, Status status, Assertion assertion) {
        ResponseBuilder responseBuilder = new ResponseBuilder();
        Response response = responseBuilder.buildObject();
        response.setID(genNewID());
        response.setIssueInstant(issueDate);
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssuer(issuer);
        response.setStatus(status);
        response.getAssertions().add(assertion);
        return response;
    }

    private String genNewID() {
        return "_" + UUID.randomUUID().toString().replaceAll("-", "");
    }

    private Assertion createAssertion(final DateTime issueDate, Subject subject, Issuer issuer, AuthnStatement authnStatement,
                                      AttributeStatement attributeStatement, Conditions conditions) {
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(genNewID());
        assertion.setIssueInstant(issueDate);
        assertion.setSubject(subject);
        assertion.setIssuer(issuer);
        assertion.setConditions(conditions);

        if (authnStatement != null)
            assertion.getAuthnStatements().add(authnStatement);

        if (attributeStatement != null)
            assertion.getAttributeStatements().add(attributeStatement);

        return assertion;
    }

    private Issuer createIssuer(final String issuerName) {
        // create Issuer object
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerName);
        return issuer;
    }

    private Subject createSubject(final String subjectId, final Integer samlAssertionDays, String aud) {
        DateTime currentDate = new DateTime();
        if (samlAssertionDays != null)
            currentDate = currentDate.plusDays(samlAssertionDays);

        // create name element
        NameIDBuilder nameIdBuilder = new NameIDBuilder();
        NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue(subjectId);
        nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");

        SubjectConfirmationDataBuilder dataBuilder = new SubjectConfirmationDataBuilder();
        SubjectConfirmationData subjectConfirmationData = dataBuilder.buildObject();
        subjectConfirmationData.setNotOnOrAfter(currentDate);
        subjectConfirmationData.setRecipient(aud);

        SubjectConfirmationBuilder subjectConfirmationBuilder = new SubjectConfirmationBuilder();
        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        // create subject element
        SubjectBuilder subjectBuilder = new SubjectBuilder();
        Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameId);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        return subject;
    }

    private AuthnStatement createAuthnStatement(final DateTime issueDate) {
        // create authcontextclassref object
        AuthnContextClassRefBuilder classRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef classRef = classRefBuilder.buildObject();
        classRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");

        // create authcontext object
        AuthnContextBuilder authContextBuilder = new AuthnContextBuilder();
        AuthnContext authnContext = authContextBuilder.buildObject();
        authnContext.setAuthnContextClassRef(classRef);

        // create authenticationstatement object
        AuthnStatementBuilder authStatementBuilder = new AuthnStatementBuilder();
        AuthnStatement authnStatement = authStatementBuilder.buildObject();
        authnStatement.setAuthnInstant(issueDate);
        authnStatement.setAuthnContext(authnContext);

        return authnStatement;
    }

    private AttributeStatement createAttributeStatement(HashMap<String, List<String>> attributes) {
        // create authenticationstatement object
        AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
        AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

        AttributeBuilder attributeBuilder = new AttributeBuilder();
        if (attributes != null) {
            for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
                Attribute attribute = attributeBuilder.buildObject();
                attribute.setName(entry.getKey());

                for (String value : entry.getValue()) {
                    XSStringBuilder stringBuilder = new XSStringBuilder();
                    XSString attributeValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                    attributeValue.setValue(value);
                    attribute.getAttributeValues().add(attributeValue);
                }

                attributeStatement.getAttributes().add(attribute);
            }
        }

        return attributeStatement;
    }

    private Status createStatus() {
        StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);

        StatusBuilder statusBuilder = new StatusBuilder();
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);

        return status;
    }

    private Signature createSignature() throws Throwable {
        if (publicKeyLocation != null && privateKeyLocation != null) {
            SignatureBuilder builder = new SignatureBuilder();
            Signature signature = builder.buildObject();
            signature.setSigningCredential(certManager.getSigningCredential(publicKeyLocation, privateKeyLocation));
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
            signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            return signature;
        }

        return null;
    }

    private Conditions createConditions(final String aud) throws Throwable {

        AudienceRestrictionBuilder audienceRestrictionBuilder = new AudienceRestrictionBuilder();
        AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();

        List<Audience> audiences = audienceRestriction.getAudiences();
        AudienceBuilder audienceBuilder = new AudienceBuilder();

        Audience audience = audienceBuilder.buildObject();
        audience.setAudienceURI(aud);
        audiences.add(audience);

        ConditionsBuilder conditionsBuilder = new ConditionsBuilder();
        Conditions conditions = conditionsBuilder.buildObject();
        conditions.getConditions().add(audienceRestriction);

        return conditions;
    }

}
