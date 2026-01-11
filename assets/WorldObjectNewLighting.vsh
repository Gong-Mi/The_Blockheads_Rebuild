//
//  Shader.vsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//
//
//
//
//attributes:[NSArray arrayWithObjects:@"position", @"texCoord", nil]\
//uniforms:[NSArray arrayWithObjects:@"mvp_matrix", @"texture",@"destruct_texture",  @"artificialLight", @"daylight", @"lightPosition", nil]]

attribute vec4 position;
attribute vec4 texCoord;

uniform mat4 mvp_matrix;
uniform vec4 lightPosition;

varying highp vec3 outTexCoord;
varying highp vec3 outLightNormal;

void main()
{
    gl_Position = mvp_matrix * vec4(position.xyz, 1.0);
    
    outTexCoord = texCoord.xyz;
    outTexCoord.z = lightPosition.w;
    
    //outLightNormal = (lightPosition.xyz - position.xyz) / 40.0;
   // outLightNormal = normalize((position.xyz - lightPosition.xyz) / 20.0 + vec3(0.0,0.0,1.0));
    
    outLightNormal = normalize((position.xyz - lightPosition.xyz) / 20.0 - vec3(-0.3,0.55,0.2));
}
