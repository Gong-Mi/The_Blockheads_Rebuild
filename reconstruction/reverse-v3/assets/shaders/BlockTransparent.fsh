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
uniform sampler2D light_texture;
uniform lowp vec4 daylight;

varying lowp vec3 outTexCoord;
varying lowp vec2 outLightTexCoord;
varying lowp float outGatherOpacity;
varying highp vec3 outLightNormal;
varying lowp vec4 outPaintColor;
varying highp vec2 outTexIndex;

void main()
{
    highp vec2 texCoord = outTexCoord.xy;
    texCoord.x = ((((texCoord.x / 255.0) * 0.984375) + 0.0078125) + outTexIndex.x) / 32.0;
    texCoord.y = ((((texCoord.y / 255.0) * 0.984375) + 0.0078125) + outTexIndex.y) / 32.0;
    
    highp vec4 tex = texture2D(texture, texCoord);
    highp vec4 destruct = texture2D(destruct_texture, texCoord);
    highp vec4 lightTex = texture2D(light_texture, outLightTexCoord);
    
    highp float outTexCoordZ = outTexCoord.z;
    highp vec4 artificialLightAddition = vec4(lightTex.xyz * (outTexCoordZ / 255.0), 0.0);
    
    destruct.b = clamp((outGatherOpacity * 1.01 - destruct.b) * 100.0, 0.0, 1.0);
    
    highp vec4 outColor = tex * destruct.b;
    
    lowp float observedDayLight = lightTex.w * daylight.w;
    
    highp vec3 light = mix(lightTex.xyz, daylight.xyz / daylight.w, observedDayLight);
    
    highp float lightDP = dot(normalize(outLightNormal + vec3((-destruct.r + 0.5) * 0.5,(destruct.g - 0.5) * 0.5,0.0)), vec3(0.0,0.0,1.0));
    
    highp float diffuse = max(((lightDP + 0.2 * (2.0 - destruct.a))), 0.2) * (1.0 + destruct.a * 0.2);
    highp float specular = destruct.a * 2.0 * (pow(diffuse, 8.0 * destruct.a) * 0.15 + diffuse * 0.2);
    
    highp vec4 baseColor = (outColor * (vec4(outPaintColor.rgb, 1.0)) + vec4(vec3(specular), 0.0) * outColor.a);
    
    gl_FragColor = baseColor * ((vec4(light * vec3(diffuse,diffuse,diffuse * 0.9 + 0.1), 1.0) + artificialLightAddition) * vec4(vec3(1.0 - outPaintColor.a * 0.5), 1.0) + vec4(outPaintColor.a, outPaintColor.a, outPaintColor.a, 0.0) * 0.5);
}
