//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;
uniform sampler2D destruct_texture;

uniform highp vec4 artificialLight;
uniform highp vec4 daylight;

varying highp vec3 outTexCoord;
varying highp vec3 outLightNormal;
uniform highp vec4 paintColor;

void main()
{
    /*lowp vec4 tex = texture2D(texture, outTexCoord.xy);
    highp vec4 destruct = texture2D(destruct_texture, outTexCoord.xy);
    
    destruct.b = clamp((outTexCoord.z * 1.01 - destruct.b) * 100.0, 0.0, 1.0);
    
    lowp vec4 outColor = tex * destruct.b;
    
    lowp float observedDayLight = artificialLight.w * daylight.w;
    lowp vec3 light = mix(artificialLight.xyz, daylight.xyz / daylight.w, observedDayLight);
    
    highp float lightDP = dot(normalize(outLightNormal - vec3((-destruct.r + 0.5),(destruct.g - 0.5),0.0) * 4.0), normalize(vec3(-0.3,0.5,0.9))) * 0.66;
    lowp float diffuse = max(((lightDP + 0.3)), 0.2);
    lowp float specular = destruct.a * (0.5 + observedDayLight * 0.5) * diffuse * diffuse;
    
    gl_FragColor = (outColor * paintColor + vec4(vec3(specular) * (light * 0.6 + vec3(0.4,0.4,0.4)), specular)) * vec4(light * vec3(diffuse,diffuse,diffuse * 0.7 + 0.3), 1.0);
    */
    
    
     
     
     highp vec4 tex = texture2D(texture, outTexCoord.xy);
     highp vec4 destruct = texture2D(destruct_texture, outTexCoord.xy);
    
     destruct.b = clamp((outTexCoord.z * 1.01 - destruct.b) * 100.0, 0.0, 1.0);
    
     lowp vec4 outColor = tex * destruct.b;
    
     highp float observedDayLight = artificialLight.w * daylight.w;
     
     highp vec3 light = mix(artificialLight.xyz, daylight.xyz / daylight.w, observedDayLight);
     
     highp float lightDP = dot(normalize(vec3(0.0,0.0,-1.0) + vec3((-destruct.r + 0.5),(destruct.g - 0.5),0.0)), outLightNormal);
     
     highp float diffuse = max((lightDP + 0.4), 0.2);
     
     highp float specular = destruct.a * 2.0 * (pow(diffuse, 8.0 * destruct.a) * 0.15 + diffuse * 0.2);
     
     
     gl_FragColor = (outColor * (vec4(paintColor.xyz, 1.0)) + vec4(vec3(specular), 0.0)) * mix(vec4(light * vec3(diffuse,diffuse,diffuse * 0.9 + 0.1), 1.0), vec4(1,1,1,1), 1.0 - paintColor.a);
     
    
    
}
