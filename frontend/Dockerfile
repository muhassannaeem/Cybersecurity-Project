# Use an official Node.js runtime as a parent image
FROM node:18-alpine

# Set the working directory in the container
WORKDIR /app

# This line receives the build argument from docker-compose.yml
ARG NEXT_PUBLIC_API_URL
# This makes the variable available to the `npm run build` command
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

# Copy package.json and package-lock.json
COPY package*.json ./

# Install application dependencies
RUN npm install

# Copy the rest of your application source code
COPY . .

# Build the Next.js application for production
RUN npm run build

# Expose the port the app runs on
EXPOSE 3000

# Command to run the production server
CMD ["npm", "start"]
