import { defineCollection, z } from 'astro:content';

const robotsCollection = defineCollection({
  type: 'data',
  schema: z.object({
    rrn: z.string(),
    name: z.string(),
    manufacturer: z.string(),
    model: z.string(),
    description: z.string(),
    status: z.enum(['active', 'retired', 'prototype', 'concept']).default('active'),
    production_year: z.number().optional(),
    specs: z.object({
      compute: z.string().optional(),
      sensors: z.array(z.string()).optional(),
      ros_version: z.array(z.string()).optional(),
      weight_kg: z.number().optional(),
      dimensions: z.string().optional(),
    }).optional(),
    verification_status: z.enum(['community', 'verified', 'manufacturer', 'certified']).default('community'),
    ruri: z.string().nullable().optional(),
    tags: z.array(z.string()).default([]),
    submitted_by: z.string().optional(),
    submitted_date: z.string().optional(),
  }),
});

export const collections = {
  robots: robotsCollection,
};
