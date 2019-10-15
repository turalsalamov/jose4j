package org.jose4j.jwt.consumer;

import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.UncheckedJoseException;

import javax.activation.MimeType;
import javax.activation.MimeTypeParseException;

public class TypeValidator implements ErrorCodeValidator
{
    private static final String APPLICATION_PRIMARY_TYPE = "application";

    private MimeType expectedType;
    private boolean requireType;

    public TypeValidator(boolean requireType, String expectedType)
    {
        try
        {
            this.expectedType = toMediaType(expectedType);
            if (this.expectedType.getSubType().equals("*"))
            {
                throw new MimeTypeParseException("cannot use wildcard in subtype");
            }

        }
        catch (MimeTypeParseException e)
        {
            throw new UncheckedJoseException("The given expected type '"+expectedType+"' isn't a valid media type in this context.", e);
        }
        this.requireType = requireType;
    }

    @Override
    public Error validate(JwtContext jwtContext)
    {
        JsonWebStructure jsonWebThing = jwtContext.getJoseObjects().get(0);
        String type = jsonWebThing.getHeader(HeaderParameterNames.TYPE);

        return validate(type);
    }

    Error validate(String type)
    {
        if (type == null)
        {
            return requireType ? new Error(ErrorCodes.TYPE_MISSING, "No typ header parameter present in the innermost JWS/JWE") : null;
        }

        if (expectedType != null)
        {
            try
            {
                MimeType mediaType = toMediaType(type);
                if (!expectedType.match(mediaType) || mediaType.getSubType().equals("*"))
                {
                    StringBuilder msg = new StringBuilder();
                    msg.append("Invalid typ header parameter value '").append(type).append("'. Expecting '");
                    msg.append(expectedType).append("'");
                    if (expectedType.getPrimaryType().equals(APPLICATION_PRIMARY_TYPE))
                    {
                        msg.append(" or just '").append(expectedType.getSubType()).append("'");
                    }
                    msg.append(".");
                    return new Error(ErrorCodes.TYPE_INVALID, msg.toString());
                }
            }
            catch (MimeTypeParseException e)
            {
                return new Error(ErrorCodes.TYPE_INVALID, "typ header parameter value '"+type+"' not parsable as a media type " + e);
            }
        }

        return null;
    }

    MimeType toMediaType(String type) throws MimeTypeParseException
    {
        return type.contains("/") ? new MimeType(type) : new MimeType(APPLICATION_PRIMARY_TYPE, type);
    }
}

