#include "projection_update.h"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
using namespace blockheads::recovered;
static unsigned checks = 0;
static void require(bool ok, const char* message) {
    ++checks;
    if (!ok) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
static uint32_t bits(float x) { uint32_t b; std::memcpy(&b, &x, 4); return b; }
static float fadd(float a,float b) { volatile float r=a+b; return r; }
static float fsub(float a,float b) { volatile float r=a-b; return r; }
static float fmul(float a,float b) { volatile float r=a*b; return r; }
static float fdiv(float a,float b) { volatile float r=a/b; return r; }
// Independent register-level reference, not an original-runtime oracle.
static ProjectionResult reference(ProjectionInput in) {
    double d0 = in.pinchScale < 1.0 ? in.pinchScale : 1.0;
    volatile double product = 0x1.0c1524p+0 * d0;
    float angle = static_cast<float>(product);
    if (in.lane0 > in.lane1) angle = fmul(angle, fdiv(in.lane1,in.lane0));
    float cot = fdiv(1.0f, ::tanf(fdiv(angle,2.0f)));
    ProjectionResult out{};
    out.matrix[0]=fdiv(cot,fdiv(in.lane0,in.lane1));
    out.matrix[5]=cot;
    out.matrix[10]=fdiv(fadd(2048.0f,1.0f),fsub(1.0f,2048.0f));
    out.matrix[11]=-1.0f;
    out.matrix[14]=fdiv(fmul(fmul(2.0f,2048.0f),1.0f),fsub(1.0f,2048.0f));
    out.cameraZ=fdiv(fmul(in.lane1,0x1.99999ap-6f),fmul(2.0f,::tanf(fmul(angle,0.5f))));
    return out;
}
static bool same(float a,float b) { return (std::isnan(a)&&std::isnan(b)) || bits(a)==bits(b); }
static void compare(ProjectionInput in) {
    auto expected=reference(in), actual=buildProjection(in);
    for (int i=0;i<16;++i) require(same(actual.matrix[i],expected.matrix[i]),"matrix IEEE/rounding mismatch");
    require(same(actual.cameraZ,expected.cameraZ),"cameraZ IEEE/rounding mismatch");
}
int main() {
    auto square=buildProjection({1.0,1000.0f,1000.0f});
    require(square.matrix[11]==-1.0f,"helper must store -1 at float index 11");
    require(square.matrix[14]<-2.0f && square.matrix[14]>-2.01f,"near/far depth coefficient");
    require(std::fabs(square.matrix[0]-1.7320508f)<0.000001f,"square FOV literal and cotangent");
    require(std::fabs(square.cameraZ-21.650635f)<0.00001f,"cameraZ 0.025 and VFP 0.5");
    auto capped=buildProjection({2.0,1000,1000});
    require(same(capped.cameraZ,square.cameraZ),"upper pinch cap");
    const float inf=std::numeric_limits<float>::infinity();
    const float nan=std::numeric_limits<float>::quiet_NaN();
    const float dims[]={1000,600,-600,0.0f,-0.0f,inf,-inf,nan,1e-38f,1e38f};
    const double scales[]={1.0,0.5,2.0,-1.0,0.0,-0.0,1e-50,1e-8,0.99999999,inf,-inf,nan};
    for(double p:scales) for(float a:dims) for(float b:dims) compare({p,a,b});
    // Deterministic finite values probe the f64 multiply -> f32 boundary.
    uint32_t seed=0x12345678;
    for(int i=0;i<2000;++i) {
        seed=1664525u*seed+1013904223u;
        double p=static_cast<double>(seed)/4294967296.0;
        compare({p,static_cast<float>((seed%2048)+1),static_cast<float>(((seed>>12)%2048)+1)});
    }
    std::printf("PASS projection_update: %u checks (3200 inputs + anchors)\n",checks);
}
