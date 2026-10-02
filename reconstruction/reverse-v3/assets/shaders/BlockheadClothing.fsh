//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;
uniform highp vec4 daylight;
uniform highp vec4 artificalLight;
uniform highp float reflectivity;

varying highp vec4 outTexCoord;
//varying highp float lighting;
varying highp float outDirectionalLight;
varying highp vec3 outNormal;
varying highp vec3 outLightNormal;

void main()
{
    highp vec4 tex = texture2D(texture, outTexCoord.xy);
    
    highp vec3 light = daylight.rgb + artificalLight.xyz * (outDirectionalLight + 0.5);
    
    highp float lightDP = dot(normalize(outNormal), normalize(outLightNormal));
    
    highp float diffuse = max((lightDP + 0.4), 0.2);
    
    highp float specular = reflectivity * (pow(diffuse, 12.0 * reflectivity) * 0.15 + diffuse * 0.2) * 0.5;
    
    
    gl_FragColor = (tex + vec4(vec3(specular), 0.0) * tex.a) * vec4(light * vec3(diffuse,diffuse,diffuse * 0.9 + 0.1), 1.0);
}
