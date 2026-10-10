//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D blockTexture;
uniform sampler2D blockDestructTexture;
uniform lowp vec4 color;

varying lowp vec2 outTexCoord;
varying lowp vec2 outTexCoordB;

const highp mat3 tbnMat = mat3(vec3(1.0,0.0,0.0), vec3(0.0,1.0,0.0), vec3(0.0,0.0,-1.0));
//const highp vec3 outLightNormal = normalize(vec3(0.2,-0.2,-1.0));
const highp vec3 outLightNormal = normalize(vec3(0.2,-0.2,-0.5));

void main()
{
    
    highp vec4 tex = texture2D(blockTexture, outTexCoord);
    highp vec4 tileTex = texture2D(blockTexture, outTexCoordB);
    highp vec4 destruct = texture2D(blockDestructTexture, outTexCoordB);
    highp vec4 destructEgg = texture2D(blockDestructTexture, outTexCoord);
    
    destruct.rgb = (destruct.rgb + destructEgg.rgb);


    highp vec3 normalMapValue = normalize(vec3((-destruct.r + 0.5),(destruct.g - 0.5),0.9));
    highp vec3 normalizedNormal = tbnMat * normalMapValue;
    highp float lightDP = dot(normalizedNormal, outLightNormal);

    highp float diffuse = max((lightDP + 0.4), 0.2);
    
    highp float specular = destruct.a * (pow(diffuse, 8.0 * destruct.a) * 0.15 + diffuse * 0.2);
    
    
    gl_FragColor = ((tex * tileTex + vec4(vec3(specular), 0.0)) * vec4(vec3(diffuse,diffuse,diffuse * 0.9 + 0.1), 1.0) * tex.a) * color;
    
}
