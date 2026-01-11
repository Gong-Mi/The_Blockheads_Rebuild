//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;
uniform sampler2D normal_texture;

uniform highp vec4 light;
uniform highp vec4 lightPosition;

varying highp vec4 outTexCoord;

void main()
{
    highp vec4 tex = texture2D(texture, outTexCoord.xy);
    highp vec4 destruct = texture2D(normal_texture, outTexCoord.xy);
    
   // highp float lightDP = dot(normalize(normal.xyz + vec3((destruct.r - 0.5) * 4.0,(destruct.g - 0.5) * -4.0,0.0)), vec3(-0.3,1.0,0.8));
    
    highp float lightDP = dot(normalize(lightPosition.xyz + vec3((destruct.r - 0.5) * -40.0,(destruct.g - 0.5) * 40.0,0.0)), vec3(0.0,0.0,1.0));
    
    //highp float lightDP = dot(normalize(outLightNormal.xyz), vec3(0.2,1.0,0.8));
    
    lowp float specular = max((lightDP - 0.5) * 2.0, 0.0);
    lowp float diffuse = clamp((lightDP + 0.8) * 0.5 + specular, 0.2, 1.0);
    
    gl_FragColor = (tex + vec4(vec3(specular) * (light.xyz * 0.6 + vec3(0.4,0.4,0.4)), specular) * tex.a) * vec4(min(light.xyz, vec3(1.0,1.0,1.0)) * vec3(diffuse,diffuse,diffuse * 0.9 + 0.1), 1.0);
    
    
    
    //gl_FragColor = tex * light * vec4(lighting,lighting,lighting,1.0);
}
