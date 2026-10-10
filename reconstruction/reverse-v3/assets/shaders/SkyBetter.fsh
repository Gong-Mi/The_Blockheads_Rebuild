//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;
uniform lowp vec4 sunColorCloudMix;

varying highp vec4 outTexCoord;

void main()
{
    highp vec4 tex = texture2D(texture, outTexCoord.xy);
    highp vec4 cloudtex = texture2D(texture, outTexCoord.zw);
    
    gl_FragColor = mix(tex, cloudtex, sunColorCloudMix.w) * vec4(sunColorCloudMix.r, sunColorCloudMix.g, sunColorCloudMix.b, 1.0);
}
