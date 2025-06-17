# Frontend Deployment to Vercel

This guide walks you through deploying the Sanguine Scribe frontend to Vercel.

## Prerequisites

1. **Backend Deployed**: Ensure your AWS backend is deployed and accessible
2. **Vercel Account**: Sign up at [vercel.com](https://vercel.com)
3. **Domain Configured**: Ensure your domain DNS is ready

## Deployment Steps

### 1. Install Vercel CLI (Optional)

```bash
npm i -g vercel
```

### 2. Prepare Environment Variables

Create `.env.production` from the example:

```bash
cp .env.production.example .env.production
```

Edit `.env.production` with your backend URL:

```env
# Your AWS ALB endpoint (after DNS is configured)
PUBLIC_API_URL=https://staging.scribe.sanguinehost.com

# Or use the raw ALB DNS during initial setup
# PUBLIC_API_URL=https://your-alb-dns-name.ap-southeast-4.elb.amazonaws.com
```

### 3. Deploy to Vercel

#### Option A: Using Vercel CLI

```bash
# From the frontend directory
cd frontend

# Login to Vercel
vercel login

# Build locally first
pnpm build

# Deploy with prebuilt flag (recommended for Node.js compatibility)
vercel deploy --prebuilt --prod
```

**Note**: Due to Node.js version compatibility issues between local development environments and Vercel's build environment, it's recommended to build locally and deploy with the `--prebuilt` flag. This ensures consistent builds regardless of Node.js version differences.

#### Option B: Using GitHub Integration

1. Push your code to GitHub
2. Import project on [vercel.com](https://vercel.com/new)
3. Configure:
   - Framework Preset: `SvelteKit`
   - Root Directory: `frontend`
   - Build Command: `pnpm build` (auto-detected)
   - Output Directory: `.vercel/output` (auto-detected)

**Troubleshooting Build Issues**: If you encounter build failures on Vercel but the build works locally, try the CLI approach with `--prebuilt` flag instead.

### 4. Configure Environment Variables in Vercel

1. Go to your project settings on Vercel
2. Navigate to "Environment Variables"
3. Add your production variables:

```
PUBLIC_API_URL = https://staging.scribe.sanguinehost.com
PUBLIC_APP_NAME = Sanguine Scribe
PUBLIC_ENVIRONMENT = staging
```

### 5. Configure Custom Domain (Staging)

#### For `staging.scribe.sanguinehost.com`:

1. In Vercel project settings, go to "Domains"
2. Add `staging.scribe.sanguinehost.com`
3. Configure DNS in Route 53:
   - Add CNAME record: `staging.scribe` → `cname.vercel-dns.com`
   - Or add A record to Vercel's IP addresses (provided by Vercel)

#### Alternative Production Domain:

For production, you could use `scribe.sanguinehost.com` following the same process.

### 6. Configure CORS on Backend

**Critical Step**: After deploying to Vercel, you must update the backend CORS configuration to include your new Vercel domain.

1. **Note your Vercel domain** from the deployment output (e.g., `frontend-abc123-projects.vercel.app`)

2. **Update backend CORS** in `backend/src/main.rs`:
   ```rust
   let cors = CorsLayer::new()
       .allow_origin([
           "https://staging.scribe.sanguinehost.com".parse().unwrap(), // Custom domain
           "https://frontend-abc123-projects.vercel.app".parse().unwrap(), // Auto-generated domain
           "https://staging.scribe.sanguinehost.com".parse().unwrap(),
           "https://localhost:5173".parse().unwrap(), // for local dev
       ])
       .allow_credentials(true)
       .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
       .allow_headers([CONTENT_TYPE, AUTHORIZATION, ACCEPT]);
   ```

3. **Redeploy the backend**:
   ```bash
   ./scripts/deploy-backend.sh backend
   ```

**Why this is necessary**: Each Vercel deployment gets a unique domain. Without updating CORS, your frontend will be blocked by the browser's same-origin policy.

## Build Configuration

The project is already configured for Vercel with:

- ✅ `@sveltejs/adapter-vercel` installed
- ✅ Adapter configured in `svelte.config.js`
- ✅ Environment variable support
- ✅ TypeScript configuration

## API Routing

The frontend expects API routes at `/api/*`. In production:

1. **Frontend**: `https://staging.scribe.sanguinehost.com`
2. **API calls**: `https://staging.scribe.sanguinehost.com/api/*`

The `PUBLIC_API_URL` environment variable handles this routing.

## Deployment Checklist

- [ ] Backend deployed and accessible at `https://staging.scribe.sanguinehost.com`
- [ ] DNS records configured for backend
- [ ] SSL certificate validated for backend
- [ ] Environment variables set in Vercel (`PUBLIC_API_URL=https://staging.scribe.sanguinehost.com`)
- [ ] Frontend built locally: `pnpm build`
- [ ] Frontend deployed: `pnpm vercel deploy --prebuilt --prod`
- [ ] Custom domain `staging.scribe.sanguinehost.com` configured in Vercel
- [ ] DNS CNAME record added in Route 53: `staging.scribe` → `cname.vercel-dns.com`
- [ ] **CRITICAL**: CORS updated in backend to include custom domain
- [ ] Backend redeployed with new CORS configuration
- [ ] Test authentication flow end-to-end
- [ ] Test API connectivity (check browser dev tools for CORS errors)

## Troubleshooting

### API Connection Issues

1. **Check CORS**: Ensure backend allows your frontend domain
   - Add your Vercel deployment URL to the backend's CORS configuration in `backend/src/main.rs`
   - The current deployment URL format is: `https://frontend-[hash]-paperboygolds-projects.vercel.app`
   - Also add the main alias: `https://frontend-paperboygolds-projects.vercel.app`
2. **Check SSL**: Both frontend and backend must use HTTPS
3. **Check API URL**: Verify `PUBLIC_API_URL` is correct
   - Should be: `https://staging.scribe.sanguinehost.com` (not the raw ALB DNS)

### Build Failures

1. **Check logs**: Vercel provides detailed build logs
2. **Environment variables**: Ensure all required vars are set
3. **Dependencies**: Run `pnpm install` locally to verify

### Authentication Issues

1. **Cookie settings**: Backend must set `SameSite=None; Secure` for cross-domain
2. **Domain matching**: Cookies might need domain configuration

## Local Testing of Production Build

```bash
# Build production version
pnpm build

# Preview production build
pnpm preview

# With production env vars
PUBLIC_API_URL=https://staging.scribe.sanguinehost.com pnpm build
pnpm preview
```

## Monitoring

Vercel provides:
- Real-time logs
- Performance analytics
- Error tracking
- Deployment history

Access these in your Vercel dashboard.

## Next Steps

1. Set up CI/CD with GitHub Actions
2. Configure preview deployments for PRs
3. Set up monitoring and error tracking
4. Configure edge functions if needed
5. Optimize performance with Vercel Analytics

---

**Note**: The frontend will work with the Vite proxy for local development. The `PUBLIC_API_URL` is only needed for production deployments.